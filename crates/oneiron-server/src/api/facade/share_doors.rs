//! The share doors past create (OF-491): the issuer or the vault's owner
//! stops a share, and its recipient opens the shared brief. The generated
//! HTTP facade handler and the MCP dispatcher both call these through
//! `host_doors`.
//!
//! Both act as the credential's own principal, built as
//! `vault.shares.create` builds its issuer: the slip's principal ref and
//! actor class, on a handle whose reads are bound to the same credential.
//! Neither takes an actor, a revoker or a viewer from the request.
use std::sync::Arc;

use oneiron::claim::ScopedReadResult;
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron::receipt::{ShareRevokeReceipt, SharedBriefView};
use oneiron::task_verb::sdk::{ShareRevokeRequest, ShareViewRequest};
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::internal;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.shares.revoke`: the credential's principal stops a share at once,
/// at the host clock's now. Only the share's issuer or the vault's live
/// owner may; any other caller, and one naming no share, hears the engine's
/// refusal as `FORBIDDEN`.
pub(crate) async fn vault_shares_revoke(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ShareRevokeRequest,
) -> MemoryResult<ShareRevokeReceipt> {
    const VERB: &str = "vault.shares.revoke";
    let (actor, class) = principal(auth, VERB)?;
    let server = Arc::clone(server);
    let auth = auth.clone();
    tokio::task::spawn_blocking(move || {
        let memory = crate::api::credential_memory(&server.vault, Some(&auth), actor, class)
            .at(auth.locality());
        oneiron::task_verb::sdk::revoke_share_as_caller(&memory, input)
    })
    .await
    .map_err(|_| internal(VERB))?
}

/// `vault.shares.view`: the credential's principal opens a shared brief
/// under its own scoped read. A share that does not resolve for this viewer
/// and a missing one both answer `null`, with the read's receipt.
pub(crate) async fn vault_shares_view(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ShareViewRequest,
) -> MemoryResult<ScopedReadResult<Option<SharedBriefView>>> {
    const VERB: &str = "vault.shares.view";
    let (actor, class) = principal(auth, VERB)?;
    let server = Arc::clone(server);
    let auth = auth.clone();
    tokio::task::spawn_blocking(move || {
        let memory = crate::api::credential_memory(&server.vault, Some(&auth), actor, class)
            .at(auth.locality());
        oneiron::task_verb::sdk::view_shared_brief_as_caller(&memory, input)
    })
    .await
    .map_err(|_| internal(VERB))?
}

/// The credential's own principal, as the facade binds a write to one. An
/// owner-grade credential that names none is refused, as on create.
fn principal(auth: &CoreAuth, verb: &str) -> MemoryResult<(EntityId, EdgeActorClass)> {
    super::facade_actor(auth).map_err(|_| {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{verb} acts as the credential's own principal"),
            &["Present a slip paired from a link created with --principal-ref and --actor-class."],
        )
    })
}
