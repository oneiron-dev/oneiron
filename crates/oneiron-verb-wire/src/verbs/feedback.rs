//! Moved from `crates/oneiron/src/verbs/feedback.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::edit_distance::publisher::vocab::IssueCategory;
use crate::feedback::bundle::FeedbackCategory;
use crate::feedback::report::ReportDisclosure;
use crate::feedback::report::ReportKind;
use crate::feedback::report::routing::ReportDisclosureChoice;
use crate::feedback::report::routing::ReportRoute;
use serde::Deserialize;
use serde::Serialize;

/// `vault.reports.disclosure`: whether one publisher-routed report's exact
/// text may cross to its publisher, once or for that publisher.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReportDisclosureRequest {
    /// The report issue id, as `report` returned it.
    pub issue_ref: String,
    /// Approve once, stop asking for this publisher, or deny.
    pub choice: ReportDisclosureChoice,
}

/// `vault.reports.route`: the maker route one durable subject reports to.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReportRouteRequest {
    /// A lasting wire receipt, skill hash, hub reference or model row.
    pub subject_ref: String,
    /// The owner inbox, or one admitted publisher.
    pub route: ReportRoute,
}

/// The route now standing for that subject.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ReportRouteReceipt {
    pub subject_ref: String,
    pub route: ReportRoute,
    pub updated: bool,
}

/// `vault.reports.outbound`: one report issue's outbound view.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReportOutboundRequest {
    /// The report issue id, as `report` returned it.
    pub issue_ref: String,
}

/// The fixed-shape content-free evidence, its subject digest as hex.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ReportSignatureView {
    pub issue_ref: String,
    /// Blake3 of the subject reference, lowercase hex; never the reference.
    pub subject_hash: String,
    pub category: IssueCategory,
    pub kind: ReportKind,
}

/// `feedback.preview`: the subject-bound bundle as it would leave.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeedbackPreviewRequest {
    /// The report issue this feedback is about.
    pub issue_ref: String,
    /// `bug`, `papercut`, `confusion` or `feature-wish`.
    pub category: FeedbackCategory,
    /// Carry the report's own quoted note and proposal. Off, the bundle is
    /// metadata only: category, versions and subject references.
    #[serde(default)]
    pub include_text: bool,
}

/// The exact bundle, its destination and the approval that sends it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FeedbackSubjectPreview {
    pub issue_ref: String,
    pub subject_ref: String,
    /// The publisher the issue's route already resolved.
    pub publisher_ref: String,
    /// The issue's disclosure standing when previewed.
    pub disclosure: ReportDisclosure,
    /// Whether these bytes carry the report's quoted text.
    pub includes_text: bool,
    /// Send this back to send exactly these bytes.
    pub digest: String,
    /// The encoding token the bytes leave under.
    pub encoding: String,
    /// The bundle as it leaves, for the owner's reading.
    #[schemars(with = "serde_json::Value")]
    pub bundle: serde_json::Value,
    /// The configured feedback endpoint it would go to.
    pub destination: String,
    /// Names this bundle going to this destination on this owner's
    /// approval; send it back unchanged.
    pub approval: String,
    /// Send it back unchanged: one preview is one send. A preview older
    /// than an hour is refused.
    pub previewed_at: u64,
}

/// `feedback.send`: send the previewed bundle for this issue, once.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeedbackSendSubjectRequest {
    /// The report issue the preview was made for.
    pub issue_ref: String,
    /// The category exactly as previewed.
    pub category: FeedbackCategory,
    /// Whether the preview carried the report's quoted text.
    #[serde(default)]
    pub include_text: bool,
    /// The digest the preview returned for exactly this bundle.
    pub digest: String,
    /// The approval the preview returned: this bundle to that destination.
    pub approval: String,
    /// When the preview was made, as it returned it.
    pub previewed_at: u64,
}

/// What the subject-bound send did.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FeedbackSubjectSent {
    pub issue_ref: String,
    pub subject_ref: String,
    pub publisher_ref: String,
    pub digest: String,
    /// `delivered_to_channel`, or `held` when the vault's policy has not
    /// granted this feedback channel yet.
    pub outcome: String,
    pub gate_reasons: Vec<String>,
    pub approval_receipt_ref: String,
    /// Repeating the same approved send names the same logical send.
    pub logical_send_ref: String,
    /// While the Gate holds the send for the owner (`held`), the
    /// approve-once digest his one-time press must name to release it, 64
    /// lower-hex (FIX 6424), copied from the send's dispatch result. Not
    /// `digest`, which names the bundle. Absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_digest: Option<String>,
}
