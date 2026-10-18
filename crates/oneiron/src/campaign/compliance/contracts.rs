//! Typed compliance-pack amendments, owner decisions and source verification.

use serde::{Deserialize, Serialize};
use super::{ComplianceAmendmentClass, CompliancePack, ComplianceRuleKind, ComplianceSource};

/// Install and amend both name the active version they were authored against.
/// The whole cited pack goes through the existing amendment classifier.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ComplianceAmendRequest {
    pub prior_version: u32,
    pub pack: CompliancePack,
}

/// An owner decision binds the exact staged rows and the active version seen.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ComplianceApprovalRequest {
    pub prior_version: u32,
    /// Lowercase SHA-256 hex returned by amend or result.
    pub proposal_hash: String,
}

/// A human's cited verification of an existing row, not a replacement rule.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ComplianceRowVerification {
    pub jurisdiction: String,
    pub channel: String,
    pub rule_kind: ComplianceRuleKind,
    pub expected_row_version: u32,
    pub source: ComplianceSource,
    /// Unix seconds of the actual verification. Past, including stale, is valid.
    pub verified_at: u64,
}

/// Refresh only source provenance; requirement, exemptions and policy dials stay put.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ComplianceVerifyRequest {
    pub prior_version: u32,
    pub rows: Vec<ComplianceRowVerification>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ComplianceResultRequest {
    /// When supplied, return this receipt rather than the complete receipt log.
    #[serde(default)]
    pub receipt_ref: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceOperation {
    Install,
    Amend,
    Approve,
    Reject,
    Verify,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceDisposition {
    Applied,
    PendingOwnerStamp,
    Rejected,
}

/// Issued only after the authenticated owner proof is revalidated in the write.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ComplianceOwnerStamp {
    pub owner_ref: String,
    pub proposal_hash: String,
    pub recorded_at: u64,
}

/// Persisted in the same transaction as the proposal, activation or rejection.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ComplianceReceipt {
    pub receipt_ref: String,
    pub operation: ComplianceOperation,
    pub disposition: ComplianceDisposition,
    pub prior_version: u32,
    pub effective_version: u32,
    pub proposed_version: u32,
    /// A stale proposal can still be rejected even when it no longer classifies.
    pub class: Option<ComplianceAmendmentClass>,
    pub proposal_hash: String,
    pub actor_ref: String,
    pub owner_stamp: Option<ComplianceOwnerStamp>,
    pub notice: Option<String>,
    pub reason_codes: Vec<String>,
    pub recorded_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CompliancePendingProposal {
    pub pack: CompliancePack,
    pub proposal_hash: String,
}

/// Active rows, the exact pending proposal, notices and authority receipts,
/// read from one snapshot. Dispatch continues to read this same active pack.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ComplianceResult {
    pub active: CompliancePack,
    pub pending: Option<CompliancePendingProposal>,
    pub notices: Vec<String>,
    pub receipts: Vec<ComplianceReceipt>,
}
