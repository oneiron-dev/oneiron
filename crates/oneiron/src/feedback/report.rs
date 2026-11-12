//! OF-537: free, actor-bound reports about a durable subject, never a task kind.

mod delivery;
mod disclosure;
mod routing;
mod store;

pub use crate::edit_distance::publisher::IssueCategory;
pub(crate) use delivery::received_issue_signature;
pub use delivery::{
    COACH_FEEDBACK_DELIVERY_FACET, REPORT_SIGNATURE_LANE, REPORT_SIGNATURE_SCHEMA,
    REPORT_SIGNATURE_VERB, ReportDeliveryHold, ReportDeliveryKey, ReportDeliveryOutcome,
    ReportDeliveryPass, ReportDeliveryRecord, ReportDeliveryRetryRequest, ReportDeliveryRun,
    ReportDeliveryRunRequest, ReportDeliveryStatus, ReportDeliveryStatusRequest, ReportFrozenSend,
    ReportFrozenSignature, ReportPublisherBinding, ReportPublisherBindingRequest,
    ReportPublisherEndpoint, ReportPublisherMetadata, ReportSignatureTransport,
    ReportSignatureTransportRequest,
};
pub use disclosure::{ReportDisclosureBasis, ReportTextSendBinding};
pub use routing::{ReportDisclosureChoice, ReportRoute, ReportRoutedPayload, ReportSignature};

use super::{FEEDBACK_REF_MAX_BYTES, FeedbackProposal};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};

pub const REPORT_VERB: &str = "report";

#[doc(hidden)]
pub use oneiron_verb_wire::feedback::report::{
    ReportDisclosure, ReportKind, ReportReview, ReportStatus,
};
#[doc(hidden)]
pub(super) use oneiron_verb_wire::feedback::report::{invalid, validate_ref};

/// Only the subject and category participate in identity; the host supplies the actor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReportRequest {
    /// A lasting wire receipt, decision, skill hash, hub reference, docs URL or model row.
    pub subject_ref: String,
    pub category: IssueCategory,
    #[serde(default)]
    pub kind: ReportKind,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub why: Option<String>,
    #[serde(default)]
    pub proposal: Option<FeedbackProposal>,
}

impl ReportRequest {
    pub fn validate(&self) -> Result<()> {
        validate_ref(&self.subject_ref)?;
        // Every evidence reference is kept, in order; how many is measured
        // where the report is recorded, never refused (FIX 8746).
        for reference in &self.evidence_refs {
            validate_ref(reference)?;
        }
        // Text of any length; its length is measured where the report is
        // recorded, never refused.
        for text in [&self.note, &self.why].into_iter().flatten() {
            if text.trim().is_empty() {
                return Err(invalid("invalid report text"));
            }
        }
        if (self.kind == ReportKind::Proposal) != self.proposal.is_some() {
            return Err(invalid("a proposal report must carry its problem and fix"));
        }
        if let Some(proposal) = &self.proposal {
            proposal
                .validate()
                .map_err(|_| invalid("invalid report proposal"))?;
        }
        Ok(())
    }

    /// Text supplied by the reporter, never text loaded from the cited vault rows.
    pub fn embedding_text(&self) -> Option<String> {
        let mut parts: Vec<&str> = [&self.note, &self.why]
            .into_iter()
            .filter_map(|text| text.as_deref())
            .collect();
        if let Some(proposal) = &self.proposal {
            parts.extend([proposal.problem.as_str(), proposal.fix.as_str()]);
        }
        (!parts.is_empty()).then(|| parts.join("\n"))
    }

    pub fn carries_text(&self) -> bool {
        self.note.is_some() || self.why.is_some() || self.proposal.is_some()
    }

    /// Bytes of the longest text the reporter wrote: what a submit measures,
    /// never a bound.
    fn longest_text(&self) -> usize {
        let proposal = self
            .proposal
            .iter()
            .flat_map(|proposal| [&proposal.problem, &proposal.fix]);
        [&self.note, &self.why]
            .into_iter()
            .flatten()
            .chain(proposal)
            .map(String::len)
            .max()
            .unwrap_or_default()
    }
}

/// A provenance-carrying ISSUE record. Free text is untrusted data, not routing policy.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReportIssue {
    pub issue_ref: String,
    pub actor_ref: String,
    pub request: ReportRequest,
    pub received_at: u64,
    pub route: ReportRoute,
    pub review: ReportReview,
    /// The effective view: what `disclosure_basis` and the live consent
    /// registry give when the issue is read (FIX 8747).
    pub disclosure: ReportDisclosure,
    /// Why the text may reach its publisher, when it may: the owner's
    /// issue-once approval, or a standing grant live now.
    pub disclosure_basis: Option<ReportDisclosureBasis>,
    /// Number of Deny choices on the issue / disclosure consent round (FIX 9368).
    #[serde(default)]
    pub disclosure_round: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportReceipt {
    pub issue_ref: String,
    pub already_submitted: bool,
    pub status: ReportStatus,
    pub quality_score: Option<f32>,
    pub duplicate_of: Option<String>,
    pub route: ReportRoute,
    pub disclosure: ReportDisclosure,
    /// Why the text may reach its publisher, when it may (FIX 8747).
    pub disclosure_basis: Option<ReportDisclosureBasis>,
}

impl ReportReceipt {
    pub(super) fn from_issue(issue: &ReportIssue, already_submitted: bool) -> Self {
        Self {
            issue_ref: issue.issue_ref.clone(),
            already_submitted,
            status: issue.review.status,
            quality_score: issue.review.quality_score,
            duplicate_of: issue.review.duplicate_of.clone(),
            route: issue.route.clone(),
            disclosure: issue.disclosure,
            disclosure_basis: issue.disclosure_basis.clone(),
        }
    }
}
