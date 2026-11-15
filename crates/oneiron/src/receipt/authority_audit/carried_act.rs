//! An act on a vault setting and an owner's whole-vault export in the audit
//! (FIX 4624, FIX 5660). A setting act's subject is its target (the
//! setting's reserved target, or the agent a free-time policy is for) and
//! its detail the setting and whether it set or cleared it; an agent's act
//! names its agent as holder and its Grant. An export's subject is the owner
//! whose copy it was and its detail the format. Never a setting's value nor
//! a byte of the copy: the record keeps only their digests.
//!
//! The web sign-in setting is the one whose value does not say what the act
//! did: only the value over the owner keys the vault had held switches it
//! back, and every other value asks for an owner key again. Its detail is
//! what the fold landed ([`web_sign_in_detail`]).

use super::{AuthorityAuditEventKind, OpFields};
use crate::authority::WebSignInAct;
use oneiron_authority::authority::{ActBy, ExportActRecord, PolicySetting, PolicySettingSet};

/// The class, op name and fields of one setting act.
pub(super) fn classify_policy_setting(
    set: &PolicySettingSet,
) -> (AuthorityAuditEventKind, &'static str, OpFields) {
    let (holder_ref, grant_ref) = match set.act.by {
        ActBy::Owner => (None, None),
        ActBy::Agent { agent, grant } => (Some(agent.to_hex()), Some(grant.to_hex())),
    };
    let change = if set.value.is_some() { "set" } else { "clear" };
    (
        AuthorityAuditEventKind::Other,
        "policy_setting",
        OpFields {
            detail: Some(format!("{} {change}", set.setting.wire())),
            subject_ref: Some(set.act.target.to_hex()),
            grant_ref,
            holder_ref,
            ..OpFields::default()
        },
    )
}

/// The detail of an act on the web sign-in setting, by what the fold landed
/// for its entry (`landed`, from [`crate::authority::AuthorityFold::web_sign_in_acts`]),
/// never by the value it carries: `set` for the owner's switch back to web
/// sign-in, `clear` for an act that landed as "ask for an owner key again",
/// `not_landed` for one the fold did not land: it waits for the owner's
/// proof, was refused, or is not a valid entry.
/// None for every other setting's act: [`classify_policy_setting`] gives its
/// detail.
pub(super) fn web_sign_in_detail(
    set: &PolicySettingSet,
    landed: Option<WebSignInAct>,
) -> Option<String> {
    if set.setting != PolicySetting::WebSignIn {
        return None;
    }
    let change = match landed {
        Some(WebSignInAct::SwitchedBack) => "set",
        Some(WebSignInAct::AsksAgain) => "clear",
        None => "not_landed",
    };
    Some(format!("{} {change}", set.setting.wire()))
}

/// The class, op name and fields of one export act.
pub(super) fn classify_export(
    record: &ExportActRecord,
) -> (AuthorityAuditEventKind, &'static str, OpFields) {
    (
        AuthorityAuditEventKind::Other,
        "export_act",
        OpFields {
            detail: Some(record.format.clone()),
            subject_ref: Some(record.act.owner.to_hex()),
            ..OpFields::default()
        },
    )
}
