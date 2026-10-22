//! The host doors of one proposed claim's review and settlement (DOOR-115):
//! `vault.claims.review` and `vault.claims.settle`. `host_doors` re-exports
//! them, so the generated HTTP facade handler and the MCP dispatcher call
//! them by the name every host door has, and a tool call, a code-mode call
//! and an SDK call meet one admission: the vault owner's proof, as
//! `/v1/owner` takes it (`owner_routes::owner`). The engine checks that
//! proof again in the writer that settles.
//!
//! Each acts on the caller's own credential handle, at its locality, so the
//! claim is read under the caller's own read scope, and lists the rows its
//! reads derived the answer from (`host_door_lists`).
use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{
    ClaimProposalReview, ClaimProposalReviewRequest, ClaimSettleRequest, ClaimSettlement,
    MemoryResult,
};
use oneiron::runtime_hooks::InvocationId;
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::support::{Listed, credential_listing, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// The vault owner's proof from the request, as `/v1/owner` takes it.
fn owner(server: &SyncServer, auth: &CoreAuth, verb: &str) -> MemoryResult<AuthenticatedOwner> {
    super::owner_binding::facade_owner(server, auth, verb)
}

/// `vault.claims.review`: one proposed claim and the handle that settles it.
pub(crate) async fn vault_claims_review(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: ClaimProposalReviewRequest,
) -> Listed<ClaimProposalReview> {
    const VERB: &str = "vault.claims.review";
    let proof = match owner(server, auth, VERB) {
        Ok(proof) => proof,
        Err(refusal) => return refused(refusal),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.claim_review_as_owner(&proof, &input)
    })
    .await
}

/// `vault.claims.settle`: the owner approves or rejects exactly the
/// reviewed claim and keeps its Settlement.
pub(crate) async fn vault_claims_settle(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: ClaimSettleRequest,
) -> Listed<ClaimSettlement> {
    const VERB: &str = "vault.claims.settle";
    let proof = match owner(server, auth, VERB) {
        Ok(proof) => proof,
        Err(refusal) => return refused(refusal),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.claim_settle_as_owner(&proof, &input)
    })
    .await
}
