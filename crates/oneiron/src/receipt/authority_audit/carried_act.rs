//! An act on a vault setting and an owner's whole-vault export in the audit
//! (FIX 4624, FIX 5660). A setting act's subject is its target (the
//! setting's reserved target, or the agent a free-time policy is for) and
//! its detail the setting and whether it set or cleared it; an agent's act
//! names its agent as holder and its Grant. An export's subject is the owner
//! whose copy it was and its detail the format. Never a setting's value nor
//! a byte of the copy: the record keeps only their digests.

use super::{AuthorityAuditEventKind, OpFields};
use crate::authority::{ActBy, ExportActRecord, PolicySettingSet};

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
