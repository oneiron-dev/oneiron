//! The e-sign rule pack (ARCH-0064 section 2 "Reminders, expiry and compliance are pack data" and
//! section 8): the lifecycle default row and the compliance rows, versioned and agent-amendable in
//! the OF-404 shape. `oneiron` re-exports each item beside the e-sign doors.

use crate::blob_artifact::esign::lifecycle::EsignLifecycleRules;
use serde::Deserialize;
use serde::Serialize;

/// The one e-sign rule pack's id.
pub const ESIGN_RULES_PACK_ID: &str = "esign.rules";

/// The UETA section 10 row: the ceremony's review-before-complete step. It is the one
/// non-waivable row (ARCH-0064 section 8); no amend, install or owner stamp waives,
/// rewrites or removes it.
pub const ESIGN_UETA_REVIEW_ROW: &str = "us.ueta.s10.review_before_complete";

/// The e-sign rule pack as it is active, staged or proposed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignRulePack {
    pub pack_id: String,
    /// Every amend advances it by at least one.
    pub pack_version: u32,
    /// The lifecycle default row: a draft created without `lifecycle` carries a copy of the
    /// active row, so a later amend never changes a document already drafted.
    pub lifecycle: EsignLifecycleRules,
    /// The compliance rows, one id each.
    pub rows: Vec<EsignComplianceRow>,
}

/// One compliance row: law as cost data the agent reads (ARCH-0064 section 8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignComplianceRow {
    /// Stable row id, e.g. [`ESIGN_UETA_REVIEW_ROW`].
    pub id: String,
    /// The legal regime the row cites, e.g. `US UETA/ESIGN`.
    pub regime: String,
    pub kind: EsignComplianceRowKind,
    /// `false` only for a genuinely non-waivable legal requirement.
    pub waivable: bool,
    /// What the row asks, in words.
    pub rule: String,
    pub source: EsignComplianceSource,
    /// Unix seconds when the citation was last checked.
    pub verified_at: u64,
    /// The row's own version, at least 1.
    pub version: u32,
}

/// What kind of law a row carries.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum EsignComplianceRowKind {
    /// A legal requirement the ceremony meets.
    Requirement,
    /// An optional accommodation a deployment may switch on.
    Accommodation,
    /// Settled law or presumption mechanics, for the agent's reading.
    Informational,
    /// Law that applies only under a stated condition.
    Conditional,
}

/// The citation behind a row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignComplianceSource {
    pub citation: String,
    pub url: String,
}

/// `vault.esign.rules.get`: no arguments.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignRulesGetRequest {}

/// `vault.esign.rules.amend`: a whole proposed pack against the active version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignRulesAmendRequest {
    /// The active version the proposal was written against.
    pub prior_version: u32,
    pub pack: EsignRulePack,
}

/// `vault.esign.rules.approve` and `vault.esign.rules.reject`: the owner's decision on the exact
/// staged proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignRulesDecisionRequest {
    /// The active version the decision was taken against.
    pub prior_version: u32,
    /// The staged proposal's hash, 64 lowercase hex characters.
    pub proposal_hash: String,
}

/// What an amend or an owner decision did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EsignRulesDisposition {
    /// The proposal is the active pack now; `notice` names it.
    Applied,
    /// The proposal is staged until the owner stamps its exact hash.
    PendingOwnerStamp,
    /// The owner rejected the staged proposal; the active pack is unchanged.
    Rejected,
}

/// The answer to an amend, approve or reject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignRulesReceipt {
    pub disposition: EsignRulesDisposition,
    /// The active version after the act.
    pub active_version: u32,
    /// The proposal's hash, 64 lowercase hex characters.
    pub proposal_hash: String,
    /// The durable activation notice, when the act activated a pack.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notice: Option<String>,
}

/// The staged proposal and the hash an owner stamp must bind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignRulesPending {
    pub pack: EsignRulePack,
    pub proposal_hash: String,
}

/// `vault.esign.rules.get`: the active pack, the staged proposal and every activation notice,
/// read in one snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignRulesView {
    pub active: EsignRulePack,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<EsignRulesPending>,
    /// Oldest version first.
    pub notices: Vec<String>,
}
