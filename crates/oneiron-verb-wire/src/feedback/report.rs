//! Moved from `crates/oneiron/src/feedback/report.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::edit_distance::publisher::vocab::IssueCategory;
use crate::feedback::bundle::FEEDBACK_REF_MAX_BYTES;
pub use crate::feedback::report::delivery::REPORT_SIGNATURE_LANE;
pub use crate::feedback::report::delivery::ReportDeliveryHold;
pub use crate::feedback::report::delivery::ReportDeliveryKey;
pub use crate::feedback::report::delivery::ReportDeliveryOutcome;
pub use crate::feedback::report::delivery::ReportDeliveryRecord;
pub use crate::feedback::report::delivery::ReportFrozenSend;
pub use crate::feedback::report::delivery::ReportFrozenSignature;
pub use crate::feedback::report::delivery::ReportPublisherEndpoint;
pub use crate::feedback::report::delivery::owner::ReportDeliveryRun;
pub use crate::feedback::report::delivery::owner::ReportDeliveryRunRequest;
pub use crate::feedback::report::delivery::owner::ReportDeliveryStatus;
pub use crate::feedback::report::delivery::owner::ReportDeliveryStatusRequest;
pub use crate::feedback::report::delivery::owner::ReportPublisherBinding;
pub use crate::feedback::report::delivery::owner::ReportPublisherBindingRequest;
pub use crate::feedback::report::delivery::retry::ReportDeliveryRetryRequest;
pub use crate::feedback::report::disclosure::ReportDisclosureBasis;
pub use crate::feedback::report::routing::ReportDisclosureChoice;
pub use crate::feedback::report::routing::ReportRoute;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use serde::Deserialize;
use serde::Serialize;

#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ReportKind {
    #[default]
    Problem,
    Proposal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReportStatus {
    Accepted,
    NeedsMoreEvidence,
    Duplicate,
    Rejected,
    Queued,
}

/// Review is on the ISSUE entity; no queue row owns a second review state.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReportReview {
    pub status: ReportStatus,
    pub quality_score: Option<f32>,
    pub duplicate_of: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReportDisclosure {
    Local,
    ContentFree,
    NeedsApproval,
    Approved,
    Denied,
}

pub fn invalid(message: &str) -> Error {
    Error::InvalidConfig(message.into())
}

pub fn validate_ref(reference: &str) -> Result<()> {
    if reference.is_empty()
        || reference.len() > FEEDBACK_REF_MAX_BYTES
        || reference
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(invalid("invalid report reference"));
    }
    Ok(())
}
pub mod delivery;
pub mod disclosure;
pub mod routing;
