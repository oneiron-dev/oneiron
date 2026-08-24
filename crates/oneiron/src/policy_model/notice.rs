//! The one notice a policy verdict emits — and the one audit row it files.
//!
//! Every notice to a READER goes to the same audience, the person AND the
//! model, with the same body. There is no sanitized variant for one reader and
//! a detailed variant for another: a verdict the model is told about is a
//! verdict the person is told about, in the same words.
//!
//! [`policy_model_rationale_notice`] is not a notice to a reader. It is an
//! AUDIT row addressed to the substrate owner reading their own receipts,
//! carrying the safeguard model's stated reason so the policy that produced it
//! can be improved. It rides the same ledger vector because that vector is what
//! a gate receipt persists, and it names its own audience so a host rendering
//! notices to a person can filter it out. It is appended LAST, so it can never
//! become the single body a caller surfaces.

use crate::store::{
    GATE_SYSTEM_NOTICE_ACTION_LABEL_MAX_LEN, GATE_SYSTEM_NOTICE_ACTION_TARGET_MAX_LEN,
    GATE_SYSTEM_NOTICE_BODY_MAX_LEN, GATE_SYSTEM_NOTICE_ROW_REF_MAX_LEN, GateSystemNoticeAction,
    GateSystemNoticeRecord,
};

use super::planes::{HostedLegalPolicy, PolicyPlane};
use super::request::PolicyModelConfig;
use super::verdict::{PolicyClassifyDecision, PolicyClassifyVerdict, PolicyVerdictCategory};

pub(crate) const SYSTEM_NOTICE_CHANNEL: &str = "policy.notice";
/// The audit channel. Separate from [`SYSTEM_NOTICE_CHANNEL`] so a host can
/// route reader-facing notices and audit rows apart without inspecting bodies.
pub(crate) const SYSTEM_NOTICE_CHANNEL_AUDIT: &str = "policy.audit";
pub(crate) const SYSTEM_NOTICE_VOICE_SYSTEM: &str = "system";
pub(crate) const SYSTEM_NOTICE_AUDIENCE_USER_AND_MODEL: &str = "user_and_model";
/// Addressed to neither the person nor the model: the substrate owner reading
/// their own receipts.
pub(crate) const SYSTEM_NOTICE_AUDIENCE_AUDIT: &str = "audit";
pub(crate) const SYSTEM_NOTICE_TYPE_WARN: &str = "policy_warn";
pub(crate) const SYSTEM_NOTICE_TYPE_BLOCK: &str = "policy_block";
pub(crate) const SYSTEM_NOTICE_TYPE_HELP_CARD: &str = "policy_help_card";
pub(crate) const SYSTEM_NOTICE_TYPE_MODEL_RATIONALE: &str = "policy_model_rationale";

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
        setting_change_offer: safe_setting_change_offer(config.owner_setting_change_offer.as_ref()),
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

/// The audit row carrying the safeguard model's own stated reason, or `None`
/// when the pass obtained no rationale (the model was not called, or the
/// declared output contract does not carry one).
///
/// The body is the model's words, bounded and otherwise untouched — the engine
/// neither summarizes nor rewrites what it recorded.
///
/// `pass_plane` is the plane the CALL ran under, and every call site knows it
/// statically. It is passed rather than derived because a verdict's category
/// names no plane on a clean allow — and a clean allow with a rationale is
/// precisely the row the design keeps: an `Escalate` pattern fired, the model
/// looked and answered `violation: 0`, and its reason is the pattern-tuning
/// data the substrate owner reads. Deriving the plane from the category
/// dropped exactly that row.
pub(crate) fn policy_model_rationale_notice(
    verdict: &PolicyClassifyVerdict,
    pass_plane: PolicyPlane,
    policy_version: Option<&str>,
) -> Option<GateSystemNoticeRecord> {
    let audit = verdict.audit.as_deref()?;
    let rationale = audit.model_rationale.as_deref()?.trim();
    if rationale.is_empty() {
        return None;
    }
    // The verdict's own attribution wins where it has one; the calling plane
    // is what answers for a verdict that names none.
    let plane = verdict.plane().unwrap_or(pass_plane);
    Some(GateSystemNoticeRecord {
        notice_type: SYSTEM_NOTICE_TYPE_MODEL_RATIONALE.to_owned(),
        channel: SYSTEM_NOTICE_CHANNEL_AUDIT.to_owned(),
        voice: SYSTEM_NOTICE_VOICE_SYSTEM.to_owned(),
        audience: SYSTEM_NOTICE_AUDIENCE_AUDIT.to_owned(),
        body: bounded_notice_body(rationale),
        row_ref: None,
        setting_change_offer: None,
        policy_plane: Some(plane.as_str().to_owned()),
        policy_version: match plane {
            // The owner plane publishes no versioned document, so there is no
            // version to name; the hosted plane always has one.
            PolicyPlane::OwnerPolicy => None,
            PolicyPlane::HostedLegal => policy_version.map(str::to_owned),
        },
        docs_url: None,
    })
}

fn bounded_notice_body(value: &str) -> String {
    if value.len() <= GATE_SYSTEM_NOTICE_BODY_MAX_LEN {
        return value.to_owned();
    }
    let mut end = GATE_SYSTEM_NOTICE_BODY_MAX_LEN;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

/// The host's setting-change affordance, dropped when the ledger would refuse
/// it — the same treatment [`safe_notice_row_ref`] gives an oversized row ref,
/// and for the same reason.
///
/// `owner_setting_change_offer` is a plain `pub` field on the host's config,
/// so nothing validates it before it is copied verbatim into every non-warn,
/// non-block owner notice. Left alone, a blank or oversize label would fail
/// the whole gate append — the verdict lost, and the content unenforced,
/// because of a broken LINK. A notice missing its convenience affordance still
/// says everything the reader needs.
fn safe_setting_change_offer(
    offer: Option<&GateSystemNoticeAction>,
) -> Option<GateSystemNoticeAction> {
    let offer = offer?;
    let usable = |value: &str, max_len: usize| !value.trim().is_empty() && value.len() <= max_len;
    (usable(&offer.label, GATE_SYSTEM_NOTICE_ACTION_LABEL_MAX_LEN)
        && usable(&offer.target, GATE_SYSTEM_NOTICE_ACTION_TARGET_MAX_LEN))
    .then(|| offer.clone())
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
