//! `vault.audit_read.grant` and `vault.audit_read.revoke` (RULING
//! AUDIT-READ-POWER-LIST = B; Engine RULING AUDITREAD-GRANT-HOME = A): the
//! owner grants or revokes one person's or agent's audit_read power, the one
//! power that reads the authority audit and every receipt family. Each is
//! the owner's own act: his proof is revalidated in the write, the act is
//! recorded beside it, and `vault.authority.audit` lists it.

use crate::Vault;
use crate::access_grant::AuditReadChange;
use crate::authority::ActSurface;
use crate::consent::AuthenticatedOwner;
use crate::memory::MemoryResult;

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::audit_read::{
    AuditReadChanged, AuditReadGrantRequest, AuditReadHolderRow, AuditReadRevokeRequest,
};

/// `vault.audit_read.grant` under the owner's proof. A repeat answers
/// `changed: false`; a holder the vault does not hold is not found.
pub fn grant_audit_read_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    surface: ActSurface,
    input: AuditReadGrantRequest,
) -> MemoryResult<AuditReadChanged> {
    let change = vault.grant_audit_read(owner, surface, input.holder, input.expires_at)?;
    Ok(answer(input.holder, change))
}

/// `vault.audit_read.revoke` under the owner's proof. A repeat answers
/// `changed: false`; a holder the owner never granted is not found.
pub fn revoke_audit_read_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    surface: ActSurface,
    input: AuditReadRevokeRequest,
) -> MemoryResult<AuditReadChanged> {
    let change = vault.revoke_audit_read(owner, surface, input.holder)?;
    Ok(answer(input.holder, change))
}

fn answer(holder: crate::EntityId, change: AuditReadChange) -> AuditReadChanged {
    AuditReadChanged {
        grant_ref: change.grant_ref,
        holder,
        changed: change.changed,
        status: change.status.as_str().to_owned(),
        granted_at: change.grant.created_at,
        expires_at: change.grant.expires_at,
        revoked_at: change.grant.revoked_at,
        holders: change.holders,
    }
}
