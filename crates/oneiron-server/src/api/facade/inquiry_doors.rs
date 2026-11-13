//! The host doors of the inquiry rows (INQUIRE-1 PR 5; federation.md
//! #inquiry; Engine ruling INQUIRE-SHAPE Q2, Q4, Q7 = A). `host_doors`
//! re-exports them, so the generated HTTP facade handler and the MCP
//! dispatcher call each by its verb's name.
//!
//! - `vault.inquire`: the calling actor's own credential (`facade_actor`),
//!   on its own handle; the inquiry goes to the member's host through
//!   [`HttpInquiryTransport`], signed with this host's key.
//! - The company Owner's `vault.inquiry.route.open` and
//!   `vault.inquiry.reciprocal_grant.mint`, and the member's
//!   `vault.inquiry.answer`, `.list`, `.scope.*` and `.edge.*`: the vault
//!   owner's proof, which each engine door revalidates in its own
//!   transaction. The route open and the edge revoke also sign with the
//!   host's slip issuer.
use std::sync::Arc;

use oneiron::memory::{MEMORY_CODE_INVALID_STATE, MemoryError, MemoryResult};
use oneiron::receipt::GuestRevokeResponse;
use oneiron::runtime_hooks::InvocationId;
use oneiron::task_verb::sdk::{
    self, EmptyRequest, InquireAnswer, InquireRequest, InquiryAnswerRequest, InquiryAnswerView,
    InquiryEdgeMintRequest, InquiryEdgeRef, InquiryEdgeView, InquiryLog,
    InquiryReciprocalGrantMintRequest, InquiryReciprocalGrantMinted, InquiryRouteOpenRequest,
    InquiryRouteOpened, InquiryScopeCloseRequest, InquiryScopeClosed, InquiryScopeItemView,
    InquiryScopeItems, InquiryScopeOpenRequest,
};
use oneiron::{EdgeActorClass, EntityId};

use super::clock_ingress;
use super::host_doors::support::{Listed, credential_listing, internal, refused};
use super::legal_hold_doors::as_owner_naming;
use crate::auth::CoreAuth;
use crate::inquiry_delivery::HttpInquiryTransport;
use crate::server::SyncServer;

fn no_host_key(verb: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        format!("{verb} signs with this host's own key, and this host holds none"),
        &[],
    )
}

/// `vault.inquire`: the calling actor sends one inquiry about a member's
/// seat for its open TASK, over the member's route, signed with this
/// host's key on each call.
pub(crate) async fn vault_inquire(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: InquireRequest,
) -> Listed<InquireAnswer> {
    const VERB: &str = "vault.inquire";
    credential_listing(server, auth, caller, VERB, move |server, _, memory| {
        let issuer = server.host_issuer().ok_or_else(|| no_host_key(VERB))?;
        let transport = HttpInquiryTransport::new(issuer);
        sdk::inquire_through(&memory, &transport, input)
    })
    .await
}

/// `vault.inquiry.route.open`: the company Owner opens the route to a
/// member's vault with the slip that vault minted for this host's key.
pub(crate) async fn vault_inquiry_route_open(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: InquiryRouteOpenRequest,
) -> Listed<InquiryRouteOpened> {
    const VERB: &str = "vault.inquiry.route.open";
    let owner = match super::owner_binding::facade_owner(server, auth, VERB) {
        Ok(owner) => owner,
        Err(refusal) => return refused(refusal),
    };
    let server = Arc::clone(server);
    let answer = clock_ingress::run_blocking(move || -> MemoryResult<InquiryRouteOpened> {
        crate::api::pairing::with_issuer(&server, |issuer| {
            Ok(sdk::open_inquiry_route_as(
                server.vault(),
                &owner,
                issuer,
                input,
            ))
        })
        .map_err(|_| no_host_key(VERB))?
    })
    .await
    .unwrap_or_else(|_| Err(internal(VERB)));
    let rows = answer
        .as_ref()
        .map_or_else(|_| Vec::new(), |route| vec![route.member]);
    (answer, rows)
}

/// `vault.inquiry.reciprocal_grant.mint`: the company Owner's propose-only
/// grant to the member's vault, for the edge's Connect pact.
pub(crate) async fn vault_inquiry_reciprocal_grant_mint(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: InquiryReciprocalGrantMintRequest,
) -> Listed<InquiryReciprocalGrantMinted> {
    as_owner_naming(
        server,
        auth,
        "vault.inquiry.reciprocal_grant.mint",
        move |server, owner| sdk::mint_inquiry_reciprocal_grant_as(server.vault(), owner, input),
        |minted| vec![minted.grant, minted.world, minted.guest_actor],
    )
    .await
}

/// `vault.inquiry.edge.mint`: the member's inquiry edge to one company.
pub(crate) async fn vault_inquiry_edge_mint(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: InquiryEdgeMintRequest,
) -> Listed<InquiryEdgeView> {
    as_owner_naming(
        server,
        auth,
        "vault.inquiry.edge.mint",
        move |server, owner| sdk::mint_inquiry_edge_as(server.vault(), owner, input),
        |edge| vec![edge.grant, edge.guest_actor, edge.opened_world],
    )
    .await
}

/// `vault.inquiry.edge.revoke`: the member withdraws one inquiry edge; the
/// pact disconnect is signed with the host's slip issuer.
pub(crate) async fn vault_inquiry_edge_revoke(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: InquiryEdgeRef,
) -> Listed<GuestRevokeResponse> {
    const VERB: &str = "vault.inquiry.edge.revoke";
    let owner = match super::owner_binding::facade_owner(server, auth, VERB) {
        Ok(owner) => owner,
        Err(refusal) => return refused(refusal),
    };
    let server = Arc::clone(server);
    let answer = clock_ingress::run_blocking(move || -> MemoryResult<GuestRevokeResponse> {
        crate::api::pairing::with_issuer(&server, |issuer| {
            Ok(sdk::revoke_inquiry_edge_as(
                server.vault(),
                &owner,
                issuer,
                input,
            ))
        })
        .map_err(|_| no_host_key(VERB))?
    })
    .await
    .unwrap_or_else(|_| Err(internal(VERB)));
    let rows = answer.as_ref().map_or_else(
        |_| Vec::new(),
        |revoked| vec![revoked.grant_ref, revoked.guest_ref],
    );
    (answer, rows)
}

/// `vault.inquiry.scope.open`: one statement opened to an edge's company.
pub(crate) async fn vault_inquiry_scope_open(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: InquiryScopeOpenRequest,
) -> Listed<InquiryScopeItemView> {
    let grant = input.grant;
    as_owner_naming(
        server,
        auth,
        "vault.inquiry.scope.open",
        move |server, owner| sdk::open_inquiry_scope_as(server.vault(), owner, input),
        move |item| vec![grant, item.claim],
    )
    .await
}

/// `vault.inquiry.scope.close`: one opened statement retracted.
pub(crate) async fn vault_inquiry_scope_close(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: InquiryScopeCloseRequest,
) -> Listed<InquiryScopeClosed> {
    as_owner_naming(
        server,
        auth,
        "vault.inquiry.scope.close",
        move |server, owner| sdk::close_inquiry_scope_as(server.vault(), owner, input),
        |closed| vec![closed.grant, closed.claim],
    )
    .await
}

/// `vault.inquiry.scope.list`: an edge's opened statements.
pub(crate) async fn vault_inquiry_scope_list(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: InquiryEdgeRef,
) -> Listed<InquiryScopeItems> {
    let grant = input.grant;
    as_owner_naming(
        server,
        auth,
        "vault.inquiry.scope.list",
        move |server, owner| sdk::inquiry_scope_items_as(server.vault(), owner, input),
        move |items| {
            std::iter::once(grant)
                .chain(items.items.iter().map(|item| item.claim))
                .collect()
        },
    )
    .await
}

/// `vault.inquiry.list`: "Asked about you", for the vault's owner.
pub(crate) async fn vault_inquiry_list(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: EmptyRequest,
) -> Listed<InquiryLog> {
    as_owner_naming(
        server,
        auth,
        "vault.inquiry.list",
        move |server, owner| sdk::inquiry_log_as(server.vault(), owner, input),
        |log| log.entries.iter().map(|entry| entry.edge).collect(),
    )
    .await
}

/// `vault.inquiry.answer`: the member's answer to one pending inquiry.
pub(crate) async fn vault_inquiry_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: InquiryAnswerRequest,
) -> Listed<InquiryAnswerView> {
    let grant = input.grant;
    as_owner_naming(
        server,
        auth,
        "vault.inquiry.answer",
        move |server, owner| sdk::answer_inquiry_as(server.vault(), owner, input),
        move |_| vec![grant],
    )
    .await
}
