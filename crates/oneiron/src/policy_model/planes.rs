//! The two policy planes, the documents they enforce, and the rows they
//! contribute.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::entity_id::bytes_to_hex_lower;
use crate::gate::{OwnerRowAction, PolicyManifestResolution};

use super::contract::PolicyOutputContract;
use super::pattern::PolicyPatternRule;
use super::request::PolicyClassifyRequest;
use super::verdict::PolicyClassifyDecision;

/// Category label an owner-plane ROW carries into the rubric. Owner rows are
/// free prose, so they share one label and are told apart by `row_ref` — which
/// is also the vocabulary the owner plane's policy document answers in.
const OWNER_POLICY_CATEGORY: &str = "owner_policy";
#[doc(hidden)]
pub(super) use oneiron_records::policy_model::planes::parse_hosted_category_label;
#[doc(hidden)]
use oneiron_records::policy_model::planes::{
    HOSTED_LEGAL_CATEGORY_PREFIX, hash_field, hash_len, hash_len_bytes, strictest,
};
#[doc(hidden)]
pub use oneiron_records::policy_model::planes::{
    HostedLegalAction, HostedLegalBasis, HostedLegalBasisKind, HostedLegalPolicy, HostedLegalRow,
    HostedLegalRowBound, PolicyPlane, PolicyRubricRow,
};

/// Longest policy document the engine accepts, in bytes.
///
/// The reasoning-safeguard models this targets work best at roughly 400–600
/// tokens of policy and stay workable to around ten thousand; the bound here is
/// far above both, because it exists to keep a registration from carrying an
/// unbounded blob into storage, not to express a recommendation.
pub const POLICY_DOCUMENT_MAX_LEN: usize = 65_536;

/// Longest hosted-legal category label the engine accepts.
///
/// A SHAPE bound, not a vocabulary. The label is the host's own word for one
/// of its legal concerns and the engine has no opinion about which words are
/// meaningful — but the label rides into a gate reason code as written, so it
/// is bounded and tokenized on exactly the terms
/// [`POLICY_PATTERN_ID_MAX_LEN`] ids already are.
///
/// [`POLICY_PATTERN_ID_MAX_LEN`]: super::pattern::POLICY_PATTERN_ID_MAX_LEN
pub const POLICY_HOSTED_CATEGORY_MAX_LEN: usize = 64;

/// The owner plane's rubric. Empty when the owner has not opted in — the
/// caller is expected to check [`PolicyManifestResolution::owner_policy_enabled`]
/// first and skip classification entirely, but an empty rubric is the honest
/// answer either way.
pub(super) fn owner_rubric_rows(
    request: &PolicyClassifyRequest,
    policy: &PolicyManifestResolution,
) -> Vec<PolicyRubricRow> {
    if !policy.owner_policy_enabled() {
        return Vec::new();
    }
    policy
        .active_owner_policy_rows_for_scope(
            request.world_ref.as_deref(),
            request.project_ref.as_deref(),
        )
        .into_iter()
        .map(|row| PolicyRubricRow {
            row_ref: row.row_ref.clone(),
            plane: PolicyPlane::OwnerPolicy,
            // Owner rows share one plane label; the model answers in `row_ref`,
            // which is the only vocabulary that tells two owner rows apart.
            category: OWNER_POLICY_CATEGORY.to_owned(),
            action: if row.human.is_some() {
                PolicyClassifyDecision::Hold
            } else {
                owner_row_decision(row.action)
            },
            text: row.text,
            why: row.why.map(|why| why.text),
        })
        .collect()
}

/// The hosted legal plane's rubric.
pub(super) fn hosted_rubric_rows(policy: &HostedLegalPolicy) -> Vec<PolicyRubricRow> {
    policy
        .rows
        .iter()
        .map(|row| PolicyRubricRow {
            row_ref: row.row_ref.clone(),
            plane: PolicyPlane::HostedLegal,
            category: hosted_category_label(&row.category),
            action: row.action.decision(),
            text: row.text.clone(),
            why: None,
        })
        .collect()
}

/// The plane-qualified spelling of a hosted category. The prefix is what keeps
/// a hosted label and an owner `row_ref` from ever colliding in one namespace.
pub(super) fn hosted_category_label(category: &str) -> String {
    format!("{HOSTED_LEGAL_CATEGORY_PREFIX}{category}")
}

const fn owner_row_decision(action: OwnerRowAction) -> PolicyClassifyDecision {
    match action {
        OwnerRowAction::Warn => PolicyClassifyDecision::Warn,
        OwnerRowAction::Reword => PolicyClassifyDecision::Reword,
        OwnerRowAction::Block => PolicyClassifyDecision::Block,
        OwnerRowAction::RouteToHelp => PolicyClassifyDecision::RouteToHelp,
    }
}
