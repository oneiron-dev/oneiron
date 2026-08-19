//! The two policy planes and the rubric rows they contribute.

use crate::gate::{OwnerRowAction, PolicyManifestResolution};

use super::request::PolicyClassifyRequest;
use super::verdict::{HostedLegalCategory, PolicyClassifyDecision};

/// Category label an owner-plane row carries into the rubric. Owner rows are
/// free prose, so they share one label and are told apart by `row_ref`.
pub(crate) const OWNER_POLICY_CATEGORY: &str = "owner_policy";
const HOSTED_LEGAL_CATEGORY_PREFIX: &str = "hosted_legal/";

/// Where a rule came from. These are the only two sources of authority in the
/// engine — there is no third, engine-authored plane underneath them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyPlane {
    /// The vault owner's own rows, from the vault's policy manifest.
    OwnerPolicy,
    /// A hosted relay service's versioned legal policy.
    HostedLegal,
}

impl PolicyPlane {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OwnerPolicy => "owner_policy",
            Self::HostedLegal => "hosted_legal",
        }
    }
}

/// One row as it is shown to the classifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRubricRow {
    pub row_ref: String,
    pub plane: PolicyPlane,
    pub category: String,
    pub action: PolicyClassifyDecision,
    pub text: String,
}

/// What a hosted legal row does when it fires. There is no `RouteToHelp` arm:
/// a hosted service enforcing its own legal duty withholds or annotates, and
/// help routing is a product decision that belongs to the vault owner's plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HostedLegalAction {
    Warn,
    Block,
}

impl HostedLegalAction {
    #[must_use]
    pub const fn decision(self) -> PolicyClassifyDecision {
        match self {
            Self::Warn => PolicyClassifyDecision::Warn,
            Self::Block => PolicyClassifyDecision::Block,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedLegalRow {
    pub row_ref: String,
    pub category: HostedLegalCategory,
    pub action: HostedLegalAction,
    pub text: String,
}

/// A hosted relay service's legal policy: what it must enforce, where, and
/// under which published version.
///
/// This is never read from the vault's own policy manifest — a vault cannot
/// name the jurisdiction it is relayed under, and a caller cannot invent one
/// per request. It reaches the relay bound to an attested service identity,
/// either registered in the [`EdgeServiceRegistry`] alongside that identity or
/// handed to the relay pass by the edge that just validated it.
///
/// [`EdgeServiceRegistry`]: crate::EdgeServiceRegistry
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedLegalPolicy {
    pub jurisdiction: String,
    pub version: String,
    pub policy_hash: String,
    pub docs_url: String,
    pub rows: Vec<HostedLegalRow>,
}

/// The owner plane's rubric. Empty when the owner has not opted in — the
/// caller is expected to check [`PolicyManifestResolution::owner_policy_enabled`]
/// first and skip classification entirely, but an empty rubric is the honest
/// answer either way.
pub(crate) fn owner_rubric_rows(
    request: &PolicyClassifyRequest,
    policy: &PolicyManifestResolution,
) -> Vec<PolicyRubricRow> {
    if !policy.owner_policy_enabled() {
        return Vec::new();
    }
    policy
        .active_owner_policy_rows(request.world_ref.as_deref())
        .into_iter()
        .map(|row| PolicyRubricRow {
            row_ref: row.row_ref.clone(),
            plane: PolicyPlane::OwnerPolicy,
            category: OWNER_POLICY_CATEGORY.to_owned(),
            action: owner_row_decision(row.action),
            text: row.text.clone(),
        })
        .collect()
}

/// The hosted legal plane's rubric.
pub(crate) fn hosted_rubric_rows(policy: &HostedLegalPolicy) -> Vec<PolicyRubricRow> {
    policy
        .rows
        .iter()
        .map(|row| PolicyRubricRow {
            row_ref: row.row_ref.clone(),
            plane: PolicyPlane::HostedLegal,
            category: hosted_category_label(row.category),
            action: row.action.decision(),
            text: row.text.clone(),
        })
        .collect()
}

pub(crate) fn hosted_category_label(category: HostedLegalCategory) -> String {
    format!("{HOSTED_LEGAL_CATEGORY_PREFIX}{}", category.as_str())
}

pub(crate) fn parse_hosted_category_label(label: &str) -> Option<HostedLegalCategory> {
    HostedLegalCategory::parse(label.strip_prefix(HOSTED_LEGAL_CATEGORY_PREFIX)?)
}

const fn owner_row_decision(action: OwnerRowAction) -> PolicyClassifyDecision {
    match action {
        OwnerRowAction::Warn => PolicyClassifyDecision::Warn,
        OwnerRowAction::Block => PolicyClassifyDecision::Block,
        OwnerRowAction::RouteToHelp => PolicyClassifyDecision::RouteToHelp,
    }
}
