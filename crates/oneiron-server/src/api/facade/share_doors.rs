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
use oneiron::receipt::{ShareRevokeReceipt, SharedBriefCitation, SharedBriefView};
use oneiron::task_verb::sdk::{BriefCitationFollowRequest, ShareRevokeRequest, ShareViewRequest};
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::support::{Listed, credential_listing, refused};
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
    let caller = match principal(server, auth, VERB) {
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
    let caller = match principal(server, auth, VERB) {
        Ok(caller) => caller,
        Err(refusal) => return refused(refusal),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        oneiron::task_verb::sdk::view_shared_brief_as_caller(&memory, input)
    })
    .await
}

/// `vault.notes.follow_citation`: reopens a saved share/citation pair as
/// this credential's own principal. A revoked or unavailable share resolves
/// no citation, even when that principal can read the claim elsewhere.
pub(crate) async fn vault_notes_follow_citation(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: BriefCitationFollowRequest,
) -> Listed<ScopedReadResult<Option<SharedBriefCitation>>> {
    const VERB: &str = "vault.notes.follow_citation";
    let caller = match principal(server, auth, VERB) {
        Ok(caller) => caller,
        Err(refusal) => return refused(refusal),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        oneiron::task_verb::sdk::follow_brief_citation_as_caller(&memory, input)
    })
    .await
}

/// The credential's own principal, as the facade binds a write to one. An
/// owner-grade credential that names none is refused, as on create. The
/// facade runs it before these doors' pre chain too (FIX 1817).
pub(in crate::api::facade) fn principal(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
) -> MemoryResult<(EntityId, EdgeActorClass)> {
    super::owner_binding::facade_caller_or(server, auth, || {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{verb} acts as the credential's own principal"),
            &["Present a slip paired from a link created with --principal-ref and --actor-class."],
        )
    })
}

/// Issues a recipient-bound, view-only link under the serving host's key.
/// The engine checks the actual caller is this share's issuer or owner.
pub(crate) async fn vault_shares_issue_view_link(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: oneiron::task_verb::sdk::ShareViewLinkRequest,
) -> Listed<oneiron::task_verb::sdk::ShareViewLink> {
    const VERB: &str = "vault.shares.issue_view_link";
    let caller = match principal(server, auth, VERB) {
        Ok(caller) => caller,
        Err(refusal) => return refused(refusal),
    };
    credential_listing(server, auth, caller, VERB, move |server, _, memory| {
        let issuer = server.host_issuer().ok_or_else(|| {
            MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "share link requires the serving host issuer",
                &[],
            )
        })?;
        oneiron::task_verb::sdk::issue_share_view_link_with_issuer(&memory, issuer, input)
    })
    .await
}
