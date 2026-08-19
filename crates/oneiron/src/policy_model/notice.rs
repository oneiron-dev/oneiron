//! The one notice a policy verdict emits.
//!
//! Every notice goes to the same audience — the person AND the model — with
//! the same body. There is no sanitized variant for one reader and a detailed
//! variant for another: a verdict the model is told about is a verdict the
//! person is told about, in the same words.

use crate::store::{GATE_SYSTEM_NOTICE_ROW_REF_MAX_LEN, GateSystemNoticeRecord};

use super::planes::{HostedLegalPolicy, PolicyPlane};
use super::request::PolicyModelConfig;
use super::verdict::{PolicyClassifyDecision, PolicyVerdictCategory};

pub(crate) const SYSTEM_NOTICE_CHANNEL: &str = "policy.notice";
pub(crate) const SYSTEM_NOTICE_VOICE_SYSTEM: &str = "system";
pub(crate) const SYSTEM_NOTICE_AUDIENCE_USER_AND_MODEL: &str = "user_and_model";
pub(crate) const SYSTEM_NOTICE_TYPE_WARN: &str = "policy_warn";
pub(crate) const SYSTEM_NOTICE_TYPE_BLOCK: &str = "policy_block";
pub(crate) const SYSTEM_NOTICE_TYPE_HELP_CARD: &str = "policy_help_card";

pub(crate) const POLICY_MODEL_OWNER_WARN_NOTICE: &str = "Oneiron flagged this outbound content under one of your policy settings and delivered it unchanged.";
pub(crate) const POLICY_MODEL_OWNER_BLOCK_NOTICE: &str =
    "Oneiron withheld this outbound content because one of your policy settings asked it to.";
pub(crate) const POLICY_MODEL_HELP_CARD_NOTICE: &str =
    "Oneiron routed this turn to a help card instead of delivering the content.";
pub(crate) const POLICY_MODEL_HELP_MESSAGE: &str =
    "Support resources should be offered alongside the reply without diagnosing the person.";

/// The hosted notice-body templates, split around the one variable part (the
/// jurisdiction) so the registration guard can price them. They live as
/// constants rather than inline literals precisely so
/// [`HOSTED_NOTICE_TEMPLATE_MAX_FIXED_LEN`] cannot drift away from the strings
/// it measures.
pub(crate) const HOSTED_WARN_NOTICE_PREFIX: &str =
    "The hosted relay service flagged this content under its ";
pub(crate) const HOSTED_WARN_NOTICE_SUFFIX: &str = " legal policy and relayed it unchanged.";
pub(crate) const HOSTED_BLOCK_NOTICE_PREFIX: &str =
    "The hosted relay service withheld this content under its ";
pub(crate) const HOSTED_BLOCK_NOTICE_SUFFIX: &str = " legal policy.";

/// The most a hosted notice body can add around a jurisdiction name. The
/// ledger's body bound minus this is the room a jurisdiction has.
pub(crate) const HOSTED_NOTICE_TEMPLATE_MAX_FIXED_LEN: usize = {
    let warn = HOSTED_WARN_NOTICE_PREFIX.len() + HOSTED_WARN_NOTICE_SUFFIX.len();
    let block = HOSTED_BLOCK_NOTICE_PREFIX.len() + HOSTED_BLOCK_NOTICE_SUFFIX.len();
    if warn > block { warn } else { block }
};

/// The notice a verdict emits, or `None` when it emits none (a clean allow).
pub(crate) fn policy_notice(
    decision: PolicyClassifyDecision,
    category: &PolicyVerdictCategory,
    hosted: Option<&HostedLegalPolicy>,
    config: &PolicyModelConfig,
) -> Option<GateSystemNoticeRecord> {
    match category {
        PolicyVerdictCategory::None => None,
        PolicyVerdictCategory::OwnerPolicy { row_ref } => {
            Some(owner_notice(decision, row_ref, config))
        }
        PolicyVerdictCategory::HostedLegal {
            jurisdiction,
            policy_version,
            row_ref,
            ..
        } => Some(hosted_notice(
            decision,
            HostedAttribution {
                jurisdiction,
                policy_version,
                row_ref,
            },
            hosted,
        )),
    }
}

struct HostedAttribution<'a> {
    jurisdiction: &'a str,
    policy_version: &'a str,
    row_ref: &'a str,
}

fn owner_notice(
    decision: PolicyClassifyDecision,
    row_ref: &str,
    config: &PolicyModelConfig,
) -> GateSystemNoticeRecord {
    let row_ref = safe_notice_row_ref(row_ref);
    let body = match (decision, row_ref.as_deref()) {
        (PolicyClassifyDecision::Block, Some(row_ref)) => format!(
            "Oneiron withheld this outbound content because your policy row {row_ref} asked it to."
        ),
        (PolicyClassifyDecision::Block, None) => POLICY_MODEL_OWNER_BLOCK_NOTICE.to_owned(),
        (PolicyClassifyDecision::RouteToHelp, _) => POLICY_MODEL_HELP_CARD_NOTICE.to_owned(),
        (_, Some(row_ref)) => format!(
            "Oneiron flagged this outbound content under your policy row {row_ref} and delivered it unchanged."
        ),
        (_, None) => POLICY_MODEL_OWNER_WARN_NOTICE.to_owned(),
    };
    GateSystemNoticeRecord {
        notice_type: notice_type_for(decision).to_owned(),
        channel: SYSTEM_NOTICE_CHANNEL.to_owned(),
        voice: SYSTEM_NOTICE_VOICE_SYSTEM.to_owned(),
        audience: SYSTEM_NOTICE_AUDIENCE_USER_AND_MODEL.to_owned(),
        body,
        row_ref,
        setting_change_offer: config.owner_setting_change_offer.clone(),
        policy_plane: Some(PolicyPlane::OwnerPolicy.as_str().to_owned()),
        policy_version: None,
        docs_url: None,
    }
}

/// A hosted-legal notice names the hosted service as the source. It never
/// says "your policy": the vault owner did not write this rule and must not
/// be made to look as though they did.
fn hosted_notice(
    decision: PolicyClassifyDecision,
    attribution: HostedAttribution<'_>,
    hosted: Option<&HostedLegalPolicy>,
) -> GateSystemNoticeRecord {
    let jurisdiction = attribution.jurisdiction;
    let body = if decision == PolicyClassifyDecision::Warn {
        format!("{HOSTED_WARN_NOTICE_PREFIX}{jurisdiction}{HOSTED_WARN_NOTICE_SUFFIX}")
    } else {
        format!("{HOSTED_BLOCK_NOTICE_PREFIX}{jurisdiction}{HOSTED_BLOCK_NOTICE_SUFFIX}")
    };
    GateSystemNoticeRecord {
        notice_type: notice_type_for(decision).to_owned(),
        channel: SYSTEM_NOTICE_CHANNEL.to_owned(),
        voice: SYSTEM_NOTICE_VOICE_SYSTEM.to_owned(),
        audience: SYSTEM_NOTICE_AUDIENCE_USER_AND_MODEL.to_owned(),
        body,
        // A hosted row ref names a line in a policy the service publishes, so
        // surfacing it points the reader at something they can go read.
        row_ref: safe_notice_row_ref(attribution.row_ref),
        setting_change_offer: None,
        policy_plane: Some(PolicyPlane::HostedLegal.as_str().to_owned()),
        policy_version: Some(attribution.policy_version.to_owned()),
        docs_url: hosted.map(|hosted| hosted.docs_url.clone()),
    }
}

/// A row ref longer than the ledger allows is dropped from the notice rather
/// than aborting the verdict it describes.
fn safe_notice_row_ref(row_ref: &str) -> Option<String> {
    let row_ref = row_ref.trim();
    if row_ref.is_empty() || row_ref.len() > GATE_SYSTEM_NOTICE_ROW_REF_MAX_LEN {
        None
    } else {
        Some(row_ref.to_owned())
    }
}

const fn notice_type_for(decision: PolicyClassifyDecision) -> &'static str {
    match decision {
        PolicyClassifyDecision::RouteToHelp => SYSTEM_NOTICE_TYPE_HELP_CARD,
        PolicyClassifyDecision::Block => SYSTEM_NOTICE_TYPE_BLOCK,
        PolicyClassifyDecision::Allow | PolicyClassifyDecision::Warn => SYSTEM_NOTICE_TYPE_WARN,
    }
}

/// The single body a caller surfaces when it can only show one string.
pub(crate) fn default_system_notice(notices: &[GateSystemNoticeRecord]) -> Option<String> {
    notices.first().map(|notice| notice.body.clone())
}
