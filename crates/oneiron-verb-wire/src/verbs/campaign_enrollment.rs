//! Moved from `crates/oneiron/src/verbs/campaign_enrollment.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// The owner's press on the exact campaign hold it reviewed.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignEnrollmentApproveOnceRequest {
    /// The held enrollment's call ref, 32 hex.
    pub call_ref: String,
    /// The approve-once digest in the hold's current owner question.
    pub approval_digest: String,
}
