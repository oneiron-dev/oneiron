//! An owner's agent Grant act in the audit (FIX 5628), and the withdrawals
//! its mint pairs with: a mint is a grant and a revoke a revoke. Its subject
//! is the owner whose will it records, its grant the Grant, and a mint's
//! holder the agent it names, with the expiry the owner set (none for a Grant
//! durable until revoked). The scope stays in the signed row: no scope text
//! is copied into a page.
//!
//! A signed withdrawal pairs with a mint as its own revoke row naming the
//! same Grant: the owner's revoke act, the host's signed withdrawal
//! (`slip_grant_revoke`) or a carrier-signed membership execution. A
//! withdrawal no counted entry names (an OAuth sign-in that ended with no
//! live host to sign, FIX 22188; a membership change whose signed record is
//! pending; a peer's delete applied here) pairs on the mint's own row,
//! through the rule the consent registry's revoked view and the revoke doors
//! read (`federation::agent_grant::withdrawal`): a mint the fold counts whose
//! Grant this vault marks withdrawn has the detail [`WITHDRAWN_MINT_DETAIL`]
//! (FIX 22193). Every withdrawal this vault applied leaves that mark, so a
//! mint a signed withdrawal ended reads so too, beside that revoke row.

use super::{AuthorityAuditEventKind, AuthorityAuditRow, OpFields};
use crate::Vault;
use crate::error::Result;
use oneiron_authority::authority::{
    AgentGrantActRecord, AgentGrantChange, AuthorityOp, MembershipExecution,
};

/// The detail of a counted mint's row whose Grant this vault marks withdrawn
/// (FIX 22193), in place of `mint`.
const WITHDRAWN_MINT_DETAIL: &str = "mint; withdrawn";

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
        AgentGrantChange::Revoke { .. } => (AuthorityAuditEventKind::Revoke, "revoke", None, None),
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

/// Pairs `row`, the row of `op`, with this vault's mark of a withdrawal: when
/// `op` is an owner's signed mint the fold counts and `vault` marks the Grant
/// it made withdrawn (`Vault::signed_mint_withdrawal_marked_in_txn`), the
/// row's detail reads [`WITHDRAWN_MINT_DETAIL`]. Any other row is left as it
/// is.
///
/// # Errors
/// A store failure reading the marks.
pub(super) fn pair_marked_withdrawal(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    op: &AuthorityOp,
    row: &mut AuthorityAuditRow,
) -> Result<()> {
    if let AuthorityOp::AgentGrantAct(record) = op
        && row.fold_valid
        && vault.signed_mint_withdrawal_marked_in_txn(txn, record)?
    {
        row.detail = Some(WITHDRAWN_MINT_DETAIL.to_owned());
    }
    Ok(())
}

/// The class, op name and fields of a membership change no host issuer
/// signed, signed later by its carrier (FIX 12335): a revoke of the Grants it
/// withdrew, its subject the member whose role moved, its holder the person
/// who executed it, its detail the cause, how many Grants it withdrew and
/// whether it hands the Owner role over. Its one Grant, when it names one
/// alone, is its grant.
pub(super) fn classify_membership_execution(
    record: &MembershipExecution,
) -> (AuthorityAuditEventKind, &'static str, OpFields) {
    (
        if record.withdrawn_grants.is_empty() {
            AuthorityAuditEventKind::Other
        } else {
            AuthorityAuditEventKind::Revoke
        },
        "membership_execution",
        OpFields {
            detail: Some(format!(
                "{}; {} grants withdrawn{}",
                record.cause.wire(),
                record.withdrawn_grants.len(),
                if record.handover.is_some() {
                    "; owner handover"
                } else {
                    ""
                }
            )),
            subject_ref: Some(record.member.to_hex()),
            grant_ref: match record.withdrawn_grants.as_slice() {
                [grant] => Some(grant.to_hex()),
                _ => None,
            },
            holder_ref: Some(record.person.to_hex()),
            ..OpFields::default()
        },
    )
}
