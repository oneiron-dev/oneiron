//! An act on a vault setting and an owner's whole-vault export in the audit
//! (FIX 4624, FIX 5660). A setting act's subject is its target (the
//! setting's reserved target, or the agent a free-time policy is for) and
//! its detail the setting and whether it set or cleared it; an agent's act
//! names its agent as holder and its Grant. An export's subject is the owner
//! whose copy it was and its detail the format. Never a setting's value nor
//! a byte of the copy: the record keeps only their digests.
//!
//! A move's setting copy (stage 7a-4) names its carrier as subject, and its
//! detail how many carried rows it lists and how many acts they name.

use super::{AuthorityAuditEventKind, OpFields};
use oneiron_authority::authority::{ActBy, ExportActRecord, PolicySettingSet, SettingCopy};

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
            detail: Some(format!("{} {change}", set.setting)),
            subject_ref: Some(set.act.target.to_hex()),
            grant_ref,
            holder_ref,
            ..OpFields::default()
        },
    )
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

/// The class, op name and fields of one move's setting copy.
pub(super) fn classify_setting_copy(
    copy: &SettingCopy,
) -> (AuthorityAuditEventKind, &'static str, OpFields) {
    let names: usize = copy.rows.iter().map(|row| row.names.len()).sum();
    (
        AuthorityAuditEventKind::Other,
        "setting_copy",
        OpFields {
            detail: Some(format!("{} carried rows, {names} acts", copy.rows.len())),
            subject_ref: Some(copy.machine.to_hex()),
            ..OpFields::default()
        },
    )
}
