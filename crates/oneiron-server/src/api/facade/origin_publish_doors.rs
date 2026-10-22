//! Credential-bound host projections of the exact publish doors (FIX 6866).
//! HTTP, SDK, MCP and code mode all bind the caller here: the credential's
//! own principal, with the owner's proof when the credential carries it.
//! The engine door then admits the owner, or that principal under one live
//! Grant, in each snapshot it reads or commits in. A credential that binds
//! no principal (the host root alone) is nobody, and is refused before any
//! hook runs. The owner-only origin setup doors keep their own barrier.
use std::sync::Arc;

use oneiron::memory::origin_doors::OriginPublishProof;
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use oneiron::origin::publish::{
    OriginPublishApproveRequest, OriginPublishIdRequest, OriginPublishRequestInput,
    OriginPublishRequestView, OriginPublishReviewRequest, OriginPublishReviewView,
};

use super::host_doors::support::{Listed, credential_listing};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

fn not_a_publisher(verb: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!("{verb} is the vault owner's, or a Grant holder's"),
        &["Present the owner's credential, or an agent's own credential under its Grant."],
    )
}

/// The check a publish row's door runs before its pre chain (`door_admits`):
/// a credential that binds a principal. Its Grant is the engine's to judge.
pub(super) fn publish_admits(server: &SyncServer, auth: &CoreAuth, verb: &str) -> MemoryResult<()> {
    super::owner_binding::facade_caller_or(server, auth, || not_a_publisher(verb)).map(drop)
}

async fn as_publisher<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&Memory<'_>, &OriginPublishProof) -> MemoryResult<T> + Send + 'static,
) -> Listed<T> {
    let caller =
        match super::owner_binding::facade_caller_or(server, auth, || not_a_publisher(verb)) {
            Ok(caller) => caller,
            Err(refusal) => return (Err(refusal), Vec::new()),
        };
    let proof = match super::owner_binding::facade_owner(server, auth, verb) {
        Ok(owner) => OriginPublishProof::Owner(owner),
        Err(_) => OriginPublishProof::Member,
    };
    credential_listing(server, auth, caller, verb, move |_, _, memory| {
        act(&memory, &proof)
    })
    .await
}

pub(crate) async fn vault_code_origin_publish_request(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OriginPublishRequestInput,
) -> Listed<OriginPublishRequestView> {
    as_publisher(
        server,
        auth,
        "vault.code.origin.publish.request",
        move |memory, proof| memory.origin_publish_request_as(proof, input),
    )
    .await
}

pub(crate) async fn vault_code_origin_publish_review(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OriginPublishReviewRequest,
) -> Listed<OriginPublishReviewView> {
    as_publisher(
        server,
        auth,
        "vault.code.origin.publish.review",
        move |memory, proof| memory.origin_publish_review_as(proof, input),
    )
    .await
}

pub(crate) async fn vault_code_origin_publish_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OriginPublishIdRequest,
) -> Listed<OriginPublishRequestView> {
    as_publisher(
        server,
        auth,
        "vault.code.origin.publish.get",
        move |memory, proof| memory.origin_publish_get_as(proof, input),
    )
    .await
}

pub(crate) async fn vault_code_origin_publish_approve(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OriginPublishApproveRequest,
) -> Listed<OriginPublishRequestView> {
    as_publisher(
        server,
        auth,
        "vault.code.origin.publish.approve",
        move |memory, proof| memory.origin_publish_approve_as(proof, input),
    )
    .await
}

pub(crate) async fn vault_code_origin_publish_execute(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OriginPublishIdRequest,
) -> Listed<OriginPublishRequestView> {
    as_publisher(
        server,
        auth,
        "vault.code.origin.publish.execute",
        move |memory, proof| memory.origin_publish_execute_as(proof, input),
    )
    .await
}

pub(crate) async fn vault_code_origin_publish_cancel(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: OriginPublishIdRequest,
) -> Listed<OriginPublishRequestView> {
    as_publisher(
        server,
        auth,
        "vault.code.origin.publish.cancel",
        move |memory, proof| memory.origin_publish_cancel_as(proof, input),
    )
    .await
}
