//! The share doors past create (OF-491): the issuer or the vault's owner
//! stops a share, and its recipient opens the shared brief. The generated
//! HTTP facade handler and the MCP dispatcher both call these through
//! `host_doors`.
//!
//! Both act as the credential's own principal, built as
//! `vault.shares.create` builds its issuer: the slip's principal ref and
//! actor class, on a handle whose reads are bound to the same credential.
//! Neither takes an actor, a revoker or a viewer from the request. Each
//! answers beside the rows its reads listed (`host_door_lists`).
use std::sync::Arc;

use oneiron::claim::ScopedReadResult;
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron::receipt::{ShareRevokeReceipt, SharedBriefView};
use oneiron::task_verb::sdk::{ShareRevokeRequest, ShareViewRequest};
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::{Listed, credential_listing, refused};
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
) -> Listed<ShareRevokeReceipt> {
    const VERB: &str = "vault.shares.revoke";
    let caller = match principal(auth, VERB) {
        Ok(caller) => caller,
        Err(refusal) => return refused(refusal),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        oneiron::task_verb::sdk::revoke_share_as_caller(&memory, input)
    })
    .await
}

/// `vault.shares.view`: the credential's principal opens a shared brief
/// under its own scoped read. A share that does not resolve for this viewer
/// and a missing one both answer `null`, with the read's receipt.
pub(crate) async fn vault_shares_view(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ShareViewRequest,
) -> Listed<ScopedReadResult<Option<SharedBriefView>>> {
    const VERB: &str = "vault.shares.view";
    let caller = match principal(auth, VERB) {
        Ok(caller) => caller,
        Err(refusal) => return refused(refusal),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        oneiron::task_verb::sdk::view_shared_brief_as_caller(&memory, input)
    })
    .await
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
