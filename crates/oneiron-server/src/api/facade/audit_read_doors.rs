//! The audit_read power's host doors (RULING AUDIT-READ-POWER-LIST = B;
//! Engine RULING AUDITREAD-GRANT-HOME = A).
//!
//! - `vault.audit_read.grant` and `vault.audit_read.revoke`: the owner's own
//!   acts. `host_doors` re-exports them, so the generated HTTP facade handler
//!   and the MCP dispatcher call each by the name every host door has. Each
//!   admits the vault owner's proof (`facade_owner`), never a person's or an
//!   agent's; the engine rechecks it in its own write and records the
//!   owner's act with `surface`. Each lists the grant row it names.
//! - [`audit_reader`]: the reader an audit door acts for, the
//!   `audit_reader` proof of its verb row.
use std::sync::Arc;

use oneiron::access_grant::AuditReader;
use oneiron::authority::ActSurface;
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryResult};
use oneiron::task_verb::sdk::{
    self, AuditReadChanged, AuditReadGrantRequest, AuditReadRevokeRequest,
};

use super::FacadeApiError;
use super::host_doors::support::{Listed, owner_proof};
use super::legal_hold_doors::as_owner_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.audit_read.grant`: the owner grants one person or agent the
/// audit_read power, listing the grant row it names.
pub(crate) async fn vault_audit_read_grant(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    surface: ActSurface,
    input: AuditReadGrantRequest,
) -> Listed<AuditReadChanged> {
    as_owner_naming(
        server,
        auth,
        "vault.audit_read.grant",
        move |server, owner| sdk::grant_audit_read_as(server.vault(), owner, surface, input),
        |changed| vec![changed.grant_ref],
    )
    .await
}

/// `vault.audit_read.revoke`: the owner revokes one person's or agent's
/// audit_read power, listing the grant row it names.
pub(crate) async fn vault_audit_read_revoke(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    surface: ActSurface,
    input: AuditReadRevokeRequest,
) -> Listed<AuditReadChanged> {
    as_owner_naming(
        server,
        auth,
        "vault.audit_read.revoke",
        move |server, owner| sdk::revoke_audit_read_as(server.vault(), owner, surface, input),
        |changed| vec![changed.grant_ref],
    )
    .await
}

/// The reader the audit door `verb` acts for: the owner's own proof on an
/// owner-grade credential, else the caller's own bound credential while its
/// actor holds a live audit_read power. The engine judges that power here,
/// before the row's hooks fire, and again in the door's own read. Any other
/// caller gets the owner door's refusal.
///
/// An owner-grade credential that proves no owner (a holder's own top-scope,
/// unattenuated slip) falls back to its actor's power, as the embedded
/// [`oneiron::memory::Memory::audit_reader`] does after the owner's refusal
/// (Wonder review 8435 F2). When that actor holds none, the caller gets the
/// owner door's refusal, as before the fallback.
pub(in crate::api::facade) fn audit_reader(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
) -> MemoryResult<AuditReader> {
    if !auth.is_owner_grade() {
        return holder_reader(server, auth, verb);
    }
    match owner_proof(auth, server, verb) {
        Ok(owner) => Ok(AuditReader::Owner(owner)),
        Err(refused) if refused.code == MEMORY_CODE_FORBIDDEN => {
            holder_reader(server, auth, verb).map_err(|_| refused)
        }
        Err(error) => Err(error),
    }
}

/// The caller's own bound credential as the reader of `verb`, while its actor
/// holds a live audit_read power; else the engine's owner refusal.
fn holder_reader(server: &SyncServer, auth: &CoreAuth, verb: &str) -> MemoryResult<AuditReader> {
    let (actor, class) =
        super::facade_actor(server, auth).map_err(FacadeApiError::into_memory_error)?;
    crate::api::credential_memory(&server.vault, Some(auth), actor, class)
        .at(auth.locality())
        .audit_reader(verb)
}
