//! Typed compliance-pack amendments, owner decisions and source verification.

use super::CompliancePack;
use serde::{Deserialize, Serialize};

/// Install and amend both name the active version they were authored against.
/// The whole cited pack goes through the existing amendment classifier.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ComplianceAmendRequest {
    pub prior_version: u32,
    pub pack: CompliancePack,
}

#[doc(hidden)]
pub use oneiron_verb_wire::gate::dispatch_compliance::contracts::{
    ComplianceApprovalRequest, ComplianceDisposition, ComplianceOperation, ComplianceOwnerStamp,
    ComplianceReceipt, ComplianceResultRequest, ComplianceRowVerification, ComplianceVerifyRequest,
};

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
