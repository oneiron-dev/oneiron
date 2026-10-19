//! An owner's agent Grant act in the audit (FIX 5628): a mint is a grant and
//! a revoke a revoke. Its subject is the owner whose will it records, its
//! grant the Grant, and a mint's holder the agent it names, with the expiry
//! the owner set (none for a Grant durable until revoked). The scope stays in
//! the signed row: no scope text is copied into a page.

use super::{AuthorityAuditEventKind, OpFields};
use crate::authority::{AgentGrantActRecord, AgentGrantChange};

/// The class, op name and fields of one agent Grant act.
pub(super) fn classify(
    record: &AgentGrantActRecord,
) -> (AuthorityAuditEventKind, &'static str, OpFields) {
    let (kind, detail, holder_ref, expires_at) = match &record.change {
        AgentGrantChange::Mint {
            member, expires_at, ..
        } => (
            AuthorityAuditEventKind::Grant,
            "mint",
            Some(member.to_hex()),
            *expires_at,
        ),
        AgentGrantChange::Revoke => (AuthorityAuditEventKind::Revoke, "revoke", None, None),
    };
    (
        kind,
        "agent_grant_act",
        OpFields {
            detail: Some(detail.to_owned()),
            subject_ref: Some(record.act.owner.to_hex()),
            grant_ref: Some(record.grant.to_hex()),
            holder_ref,
            expires_at,
            ..OpFields::default()
        },
    )
}
