//! OF-537: free, actor-bound reports about a durable subject, never a task kind.

mod routing;
mod store;

pub use crate::edit_distance::publisher::IssueCategory;
pub use routing::{ReportDisclosureChoice, ReportRoute, ReportRoutedPayload, ReportSignature};

use super::{
    FEEDBACK_MAX_SUBJECT_REFS, FEEDBACK_REF_MAX_BYTES, FEEDBACK_USER_NOTE_MAX_BYTES,
    FeedbackProposal,
};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};

pub const REPORT_VERB: &str = "report";

#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ReportKind {
    #[default]
    Problem,
    Proposal,
}

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
        if self.evidence_refs.len() > FEEDBACK_MAX_SUBJECT_REFS {
            return Err(invalid("too many report evidence references"));
        }
        for reference in &self.evidence_refs {
            validate_ref(reference)?;
        }
        for text in [&self.note, &self.why].into_iter().flatten() {
            if text.trim().is_empty() || text.len() > FEEDBACK_USER_NOTE_MAX_BYTES {
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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportStatus {
    Accepted,
    NeedsMoreEvidence,
    Duplicate,
    Rejected,
    Queued,
}

/// Review is on the ISSUE entity; no queue row owns a second review state.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportReview {
    pub status: ReportStatus,
    pub quality_score: Option<f32>,
    pub duplicate_of: Option<String>,
}

impl Default for ReportReview {
    fn default() -> Self {
        Self {
            status: ReportStatus::Accepted,
            quality_score: None,
            duplicate_of: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportDisclosure {
    Local,
    ContentFree,
    NeedsApproval,
    Approved,
    Denied,
}

/// A provenance-carrying ISSUE record. Free text is untrusted data, not routing policy.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportIssue {
    pub issue_ref: String,
    pub actor_ref: String,
    pub request: ReportRequest,
    pub received_at: u64,
    pub route: ReportRoute,
    pub review: ReportReview,
    pub disclosure: ReportDisclosure,
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
        }
    }
}

pub(super) fn invalid(message: &str) -> Error {
    Error::InvalidConfig(message.into())
}

pub(super) fn validate_ref(reference: &str) -> Result<()> {
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
