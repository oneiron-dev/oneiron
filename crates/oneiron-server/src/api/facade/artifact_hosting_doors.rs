//! Typed publication and private preview doors under each caller's own proof.

use std::sync::Arc;

use oneiron::artifact_hosting::door_types::*;
use oneiron::artifact_hosting::ArtifactPointer;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{Memory, MemoryError, MemoryResult};
use oneiron::task_verb::sdk::EmptyRequest;

use super::FacadeApiError;
use super::host_doors::{Listed, credential_listing, owner_proof, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

async fn as_owner<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&Memory<'_>, &AuthenticatedOwner) -> MemoryResult<T> + Send + 'static,
) -> Listed<T> {
    let admitted = || {
        let owner = owner_proof(auth, server, verb)?;
        let caller = super::facade_actor(server, auth).map_err(FacadeApiError::into_memory_error)?;
        Ok::<_, MemoryError>((owner, caller))
    };
    let (owner, caller) = match admitted() {
        Ok(admitted) => admitted,
        Err(error) => return refused(error),
    };
    credential_listing(server, auth, caller, verb, move |_, _, memory| act(&memory, &owner)).await
}

pub(crate) async fn vault_artifacts_publish_approval(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ArtifactPublishRequest,
) -> Listed<ArtifactPublishApproval> {
    as_owner(server, auth, "vault.artifacts.publish_approval", move |memory, owner| {
        memory.artifact_publish_approval_as(owner, input)
    }).await
}

pub(crate) async fn vault_artifacts_publish(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ArtifactPublishRequest,
) -> Listed<ArtifactPublishView> {
    as_owner(server, auth, "vault.artifacts.publish", move |memory, owner| {
        memory.artifact_publish_as(owner, input)
    }).await
}

pub(crate) async fn vault_artifacts_repoint(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ArtifactPublishRequest,
) -> Listed<ArtifactPublishView> {
    as_owner(server, auth, "vault.artifacts.repoint", move |memory, owner| {
        memory.artifact_publish_as(owner, input)
    }).await
}

pub(crate) async fn vault_artifacts_pointer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ArtifactPointerRequest,
) -> Listed<Option<ArtifactPointer>> {
    as_owner(server, auth, "vault.artifacts.pointer", move |memory, owner| {
        memory.artifact_pointer_as(owner, input)
    }).await
}

pub(crate) async fn vault_artifacts_unpublish(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ArtifactPointerRequest,
) -> Listed<ArtifactUnpublished> {
    as_owner(server, auth, "vault.artifacts.unpublish", move |memory, owner| {
        memory.artifact_unpublish_as(owner, input)
    }).await
}

pub(crate) async fn vault_artifacts_link_token(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _: EmptyRequest,
) -> Listed<ArtifactLinkToken> {
    as_owner(server, auth, "vault.artifacts.link_token", |memory, owner| {
        memory.artifact_link_token_as(owner)
    }).await
}

fn preview_owner(server: &SyncServer, auth: &CoreAuth, verb: &str) -> MemoryResult<String> {
    Ok(owner_proof(auth, server, verb)?.revalidate(server.vault())?.to_hex())
}

pub(crate) async fn vault_artifacts_live_preview_register(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ArtifactPreviewRegisterRequest,
) -> Listed<ArtifactPreviewView> {
    let owner = match preview_owner(server, auth, "vault.artifacts.live_preview.register") {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    (server.artifact_previews.register(input.into_manifest(owner)).await, Vec::new())
}

pub(crate) async fn vault_artifacts_live_preview_read(
    server: &Arc<SyncServer>,
    _: &CoreAuth,
    caller: (oneiron::EntityId, oneiron::EdgeActorClass),
    _: Option<oneiron::runtime_hooks::InvocationId>,
    input: ArtifactPreviewRequest,
) -> Listed<Option<ArtifactPreviewView>> {
    (server.artifact_previews.read(&caller.0.to_hex(), input).await, Vec::new())
}

pub(crate) async fn vault_artifacts_live_preview_close(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ArtifactPreviewRequest,
) -> Listed<ArtifactPreviewClosed> {
    let owner = match preview_owner(server, auth, "vault.artifacts.live_preview.close") {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    (server.artifact_previews.close(&owner, input).await, Vec::new())
}

pub(crate) async fn vault_artifacts_live_preview_invite(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ArtifactPreviewInviteRequest,
) -> Listed<ArtifactPreviewInvitation> {
    let owner = match preview_owner(server, auth, "vault.artifacts.live_preview.invite") {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    (server.artifact_previews.invitation(&owner, input, true).await, Vec::new())
}

pub(crate) async fn vault_artifacts_live_preview_revoke_invite(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ArtifactPreviewInviteRequest,
) -> Listed<ArtifactPreviewInvitation> {
    let owner = match preview_owner(server, auth, "vault.artifacts.live_preview.revoke_invite") {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    (server.artifact_previews.invitation(&owner, input, false).await, Vec::new())
}

pub(crate) async fn vault_artifacts_live_preview_share(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ArtifactPreviewRequest,
) -> Listed<ArtifactPreviewShare> {
    let owner = match preview_owner(server, auth, "vault.artifacts.live_preview.share") {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    (server.artifact_previews.share(&owner, input, true).await, Vec::new())
}

pub(crate) async fn vault_artifacts_live_preview_revoke_share(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ArtifactPreviewRequest,
) -> Listed<ArtifactPreviewShare> {
    let owner = match preview_owner(server, auth, "vault.artifacts.live_preview.revoke_share") {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    (server.artifact_previews.share(&owner, input, false).await, Vec::new())
}
