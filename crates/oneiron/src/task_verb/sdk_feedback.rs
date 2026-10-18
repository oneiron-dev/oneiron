//! Subject-bound feedback over one report issue: its publisher disclosure,
//! its content-free outbound payload, and the feedback bundle it sends.
//! The bundle binds the issue and its subject through its healer
//! diagnosis, so the preview digest the owner approves names exactly the
//! subject, the text (when included) and, through the approval scope, the
//! destination. Delivery itself is the server host's transport over
//! [`crate::feedback::send_feedback`]; no transport lives here.
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::feedback::{
    FeedbackBundle, FeedbackCategory, FeedbackHealerDiagnosis, FeedbackPlatform, IssueCategory,
    ReportDisclosure, ReportDisclosureChoice, ReportIssue, ReportKind, ReportRequest, ReportRoute,
    ReportStatus,
};
use crate::memory::{MemoryError, MemoryResult};
use crate::{EntityId, Vault};

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

/// What a publisher delivery would carry for that issue right now.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ReportPayloadView {
    pub route: ReportRoute,
    pub signature: ReportSignatureView,
    /// The report's own text, present only when disclosure approved it.
    pub disclosed: Option<ReportRequest>,
}

/// The outbound view: no payload for a local, duplicate, rejected or
/// denied report, or one whose text still waits on disclosure.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ReportOutboundView {
    pub issue_ref: String,
    pub payload: Option<ReportPayloadView>,
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
}

fn parse_issue_ref(issue_ref: &str) -> MemoryResult<EntityId> {
    EntityId::from_hex(issue_ref)
        .map_err(|_| MemoryError::bad_request("issue_ref must be a report issue id"))
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The owner's disclosure decision on the issue itself, rechecked against
/// the owner proof inside the deciding write transaction.
pub fn decide_report_disclosure_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: ReportDisclosureRequest,
) -> MemoryResult<ReportIssue> {
    let id = parse_issue_ref(&input.issue_ref)?;
    Ok(vault.decide_report_disclosure(owner, &id, input.choice)?)
}

/// The owner's route for one subject, rechecked in the writing transaction.
pub fn set_report_route_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: ReportRouteRequest,
) -> MemoryResult<ReportRouteReceipt> {
    vault.set_report_route(owner, &input.subject_ref, input.route.clone())?;
    Ok(ReportRouteReceipt {
        subject_ref: input.subject_ref,
        route: input.route,
        updated: true,
    })
}

/// The outbound view of one issue, under the caller's own owner proof.
pub fn report_outbound_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: ReportOutboundRequest,
) -> MemoryResult<ReportOutboundView> {
    owner.revalidate(vault)?;
    let id = parse_issue_ref(&input.issue_ref)?;
    let payload = vault.report_routed_payload(&id)?.map(|payload| {
        ReportPayloadView {
            route: payload.route,
            signature: ReportSignatureView {
                issue_ref: payload.signature.issue_ref,
                subject_hash: hex(&payload.signature.subject_hash),
                category: payload.signature.category,
                kind: payload.signature.kind,
            },
            disclosed: payload.disclosed,
        }
    });
    Ok(ReportOutboundView {
        issue_ref: input.issue_ref,
        payload,
    })
}

/// One report issue read under the owner's proof; nothing if it names none.
pub fn report_issue_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    issue_ref: &str,
) -> MemoryResult<ReportIssue> {
    owner.revalidate(vault)?;
    let id = parse_issue_ref(issue_ref)?;
    vault
        .report_issue(&id)?
        .ok_or_else(|| MemoryError::from(crate::Error::EntityNotFound))
}

/// The publisher an issue's route resolved; a local report sends nowhere.
pub fn subject_feedback_publisher(issue: &ReportIssue) -> MemoryResult<String> {
    match &issue.route {
        ReportRoute::Publisher { publisher_ref } => Ok(publisher_ref.clone()),
        ReportRoute::OwnerInbox => Err(MemoryError::bad_request(
            "a local report has no publisher to send feedback to",
        )),
    }
}

/// The feedback bundle one issue sends: its subject rides the healer
/// diagnosis, and its quoted text rides only when asked for, so the
/// metadata bundle and the disclosed bundle are two digests.
#[must_use]
pub fn subject_feedback_bundle(
    issue: &ReportIssue,
    category: FeedbackCategory,
    include_text: bool,
) -> FeedbackBundle {
    let mut diagnosis = FeedbackHealerDiagnosis::new(issue.issue_ref.clone());
    diagnosis.subject_refs = BTreeSet::from([issue.request.subject_ref.clone()]);
    let mut bundle = FeedbackBundle::new(
        category,
        env!("CARGO_PKG_VERSION"),
        FeedbackPlatform::current(),
    )
    .with_healer_diagnosis(diagnosis);
    if include_text {
        let note = [
            issue.request.note.as_deref(),
            issue.request.why.as_deref(),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("\n");
        if !note.is_empty() {
            bundle = bundle.with_user_note(note);
        }
        if let Some(proposal) = &issue.request.proposal {
            bundle = bundle.with_proposal(proposal.clone());
        }
    }
    bundle
}

/// The disclosure gate a send must pass beside its bundle approval. A
/// duplicate or rejected issue, and one whose disclosure the owner
/// denied, sends nothing. A metadata bundle carries no vault text, so it
/// may leave while the issue's text still waits on disclosure; a text
/// bundle may leave only while the engine's own routed payload discloses
/// that text to this publisher (approved once, or standing).
pub fn subject_feedback_send_allowed(
    vault: &Vault,
    issue: &ReportIssue,
    include_text: bool,
) -> MemoryResult<()> {
    if matches!(
        issue.review.status,
        ReportStatus::Duplicate | ReportStatus::Rejected
    ) || issue.disclosure == ReportDisclosure::Denied
    {
        return Err(MemoryError::bad_request(
            "this report sends no feedback: it is duplicate, rejected, or its disclosure was denied",
        ));
    }
    if include_text && issue.request.carries_text() {
        let id = parse_issue_ref(&issue.issue_ref)?;
        let disclosed = vault
            .report_routed_payload(&id)?
            .is_some_and(|payload| payload.disclosed.is_some());
        if !disclosed {
            return Err(MemoryError::bad_request(
                "the quoted report text is not approved for this publisher; decide its disclosure first",
            ));
        }
    }
    Ok(())
}
