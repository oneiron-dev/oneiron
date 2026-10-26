//! A managed vault's console owner on `/mcp` (WILL-PLAN L14 row 01).
//!
//! The owner's console carries no connector credential: its supervisor
//! attests the vault's owner for one request (`ManagedOwnerAction`, verified
//! at managed ingress), or for the upgrade of his own held MCP socket, each
//! of whose calls names that socket (`ManagedOwnerSession`, FIX 5128). Such
//! a request is the owner's own call, never a paired agent's or a slip's,
//! while the vault records him as its live owner. A request that carries a
//! credential stays that credential's caller, with its registration, scope
//! and Grant.

use std::sync::Arc;

use axum::http::header::AUTHORIZATION;
use axum::http::{Extensions, HeaderMap};
use oneiron::context_board::StreamConnectionId;

use super::actor_dispatch::mcp_request_placement;
use super::{MCP_CREDENTIAL_HEADER, McpCallContext, McpGatewayError, resolve_mcp_gateway_actor};
use crate::auth::CoreAuth;
use crate::mcp::{McpConnectorScope, McpResolvedActor, McpSurfaceMode};
use crate::server::SyncServer;

/// The `blake3::derive_key` context of an attested owner's STREAM
/// connection ([`owner_stream_connection`]).
const MCP_OWNER_STREAM_CONTEXT: &str = "oneiron-server 2026-10 mcp managed-owner stream";

/// The caller of one `/mcp` request. A request that carries no connector
/// credential of its own, on a managed vault whose supervisor attested its
/// owner for it or for the held socket it came on, is that owner's own call
/// ([`managed_owner_context`]). Any other request is the registered
/// connector its credential names ([`resolve_mcp_gateway_actor`]); beside
/// an attestation that credential stays the caller, with its own bounds,
/// and must name the attested person.
pub(crate) async fn resolve_mcp_caller(
    mode: McpSurfaceMode,
    request_id: &str,
    headers: &HeaderMap,
    connection: &Extensions,
    locality: oneiron::claim::CallerLocality,
    server: &Arc<SyncServer>,
) -> Result<McpCallContext, McpGatewayError> {
    let attested = crate::auth::attested_owner(connection, server);
    let Some(owner) = attested.or_else(|| session_owner(connection, server)) else {
        return resolve_mcp_gateway_actor(mode, request_id, headers, locality, server)
            .await
            .map(|context| with_admitted_proof(context, connection));
    };
    if !headers.contains_key(MCP_CREDENTIAL_HEADER) && !headers.contains_key(AUTHORIZATION) {
        // This request's own caller, or for a call on his held socket the
        // owner himself, built again for this call.
        let auth = match attested {
            Some(_) => CoreAuth::for_managed_request(headers, connection, owner_path(mode), server)
                .and_then(Result::ok),
            None => CoreAuth::for_attested_owner(owner, server)
                .ok()
                .map(|auth| {
                    auth.at(crate::auth::caller_locality(headers, connection))
                        .toward(crate::auth::proved_peer(headers, connection))
                }),
        };
        return managed_owner_context(mode, request_id, headers, owner, auth, server);
    }
    let context = resolve_mcp_gateway_actor(mode, request_id, headers, locality, server)
        .await
        .map(|context| with_admitted_proof(context, connection))?;
    let principal = context
        .actor
        .auth
        .as_ref()
        .and_then(crate::auth::CoreAuth::principal_ref);
    if principal != Some(owner.to_hex().as_str()) {
        return Err(McpGatewayError::new(
            -32001,
            "managed_caller_conflict",
            "the connector credential this request carries names another caller than the owner \
             its supervisor attested",
        ));
    }
    Ok(context)
}

/// `context`, a call [`resolve_mcp_gateway_actor`] resolved, holding the
/// holder proof the binding door admitted its caller's slip on (FIX 6160),
/// for the home an opened device asks, in place of the one read from the
/// headers again. A caller that forwards none (owner grade, or no
/// holder-bound slip) still forwards none, and a request the door kept no
/// caller for keeps its headers' proof.
fn with_admitted_proof(mut context: McpCallContext, connection: &Extensions) -> McpCallContext {
    if context.forwarded.is_some()
        && let Some(admitted) = context
            .actor
            .auth
            .as_ref()
            .and_then(|auth| auth.admitted_forwarded_proof(connection))
    {
        context.forwarded = Some(admitted);
    }
    context
}

/// A managed vault's attested owner's own `/mcp` call: the person, as a
/// human, vault-wide, while the vault records him as its live owner. Its
/// `auth` is the request's one caller
/// ([`CoreAuth::for_managed_request`]), or on his held socket the owner
/// himself ([`CoreAuth::for_attested_owner`]), so his reads run under his
/// own key held to this call's owner proof, and each verb's own owner and
/// Grant checks judge him. No registration stands behind it: no connector
/// record, slip or bound-verb ceiling is made for him, and a call
/// settlement runs again finds none. Pagination, wakes and code runs key on
/// his own STREAM connection ([`owner_stream_connection`]).
fn managed_owner_context(
    mode: McpSurfaceMode,
    request_id: &str,
    headers: &HeaderMap,
    owner: oneiron::EntityId,
    auth: Option<CoreAuth>,
    server: &Arc<SyncServer>,
) -> Result<McpCallContext, McpGatewayError> {
    let (session, room_turn) = mcp_request_placement(headers)?;
    owner_context_at(mode, request_id, owner, auth, session, room_turn, server)
}

/// The call of a caller a facade door already built (FIX 5400): a managed
/// vault's attested owner, who carries no connector credential, is his own
/// call in `session`, as on `/mcp` ([`managed_owner_context`]). `None` for
/// any other caller, which keeps its credential's registration.
pub(crate) fn attested_owner_call(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<oneiron::EntityId>,
) -> Option<Result<McpCallContext, McpGatewayError>> {
    let owner = auth.managed_owner()?;
    Some(owner_context_at(
        McpSurfaceMode::Primary,
        "memory-proxy",
        owner,
        Some(auth.clone()),
        session,
        None,
        server,
    ))
}

/// The console owner's own tool-first call a verb hook's ask stopped, built
/// again at settlement (FIX 5204) under `auth`, the owner as
/// [`CoreAuth::for_attested_owner`] rebuilt him now: only while
/// `connection`, the STREAM the call saved, is still his own
/// ([`owner_stream_connection`]). Neither his held socket nor a registration
/// is needed; it sits in no session or room turn, as its call named none, and
/// carries the call's `invocation` and the drain's permit. `None` for a
/// stream that is not his.
#[cfg(feature = "code-sandbox-wasmtime")]
pub(super) fn owner_resume_context(
    server: &Arc<SyncServer>,
    auth: CoreAuth,
    connection: &str,
    invocation: oneiron::runtime_hooks::InvocationId,
    drain: oneiron::runtime_hooks::verb::VerbAskDrainPermit,
) -> Option<Result<McpCallContext, McpGatewayError>> {
    let owner = auth.managed_owner()?;
    if owner_stream_connection(owner).0 != connection {
        return None;
    }
    let request_id = format!("verb-ask-{}", invocation.to_hex());
    Some(
        owner_context_at(
            McpSurfaceMode::ToolFirst,
            &request_id,
            owner,
            Some(auth),
            None,
            None,
            server,
        )
        .map(|mut context| {
            context.invocation = Some(invocation);
            context.drain = Some(drain);
            context
        }),
    )
}

/// [`managed_owner_context`] once the call's placement is known.
fn owner_context_at(
    mode: McpSurfaceMode,
    request_id: &str,
    owner: oneiron::EntityId,
    auth: Option<CoreAuth>,
    session: Option<oneiron::EntityId>,
    room_turn: Option<oneiron::EntityId>,
    server: &Arc<SyncServer>,
) -> Result<McpCallContext, McpGatewayError> {
    let auth = auth
        .filter(|auth| auth.managed_owner() == Some(owner))
        .ok_or_else(owner_not_live)?;
    crate::api::scoped_auth::require_live_managed_owner(server, &auth)
        .map_err(|_| owner_not_live())?;
    let session_ref = session.map(|session| session.to_hex());
    let scope = McpConnectorScope::vault_wide();
    let actor = McpResolvedActor {
        auth: Some(auth.in_off_record_session(session_ref.as_deref())),
        actor_ref: owner,
        actor_class: oneiron::EdgeActorClass::Human,
        gate_actor_class: oneiron::EdgeActorClass::Human.gate_actor_class(),
        gate_actor_ref: owner.to_hex(),
        stream_connection: owner_stream_connection(owner),
        bound_verbs: None,
        subscription_ceiling: scope.subscription_ceiling(),
        scope,
    };
    let landing = crate::api::write_facet::landing_facet(
        &server.vault,
        session,
        &actor.scope.facets,
        actor.scope.facet_ref,
    );
    Ok(McpCallContext {
        actor,
        mode,
        request_id: request_id.to_owned(),
        landing,
        invocation: None,
        hook_ask: None,
        off_record_session: session_ref,
        room_turn,
        drain: None,
        forwarded: None,
    })
}

/// The refusal of an owner's call the vault no longer records him as its
/// live owner for, told to sign in again (FIX 5327).
fn owner_not_live() -> McpGatewayError {
    McpGatewayError::new(
        -32001,
        "mcp_auth_required",
        format!(
            "the attested owner is not this vault's live owner. {}",
            crate::error::MANAGED_OWNER_SIGN_IN_AGAIN
        ),
    )
}

/// The route an owner's call on `mode` names, where its caller is placed.
pub(super) fn owner_path(mode: McpSurfaceMode) -> &'static str {
    match mode {
        McpSurfaceMode::Primary => crate::cli::McpSurface::Primary.path(),
        McpSurfaceMode::ToolFirst => crate::cli::McpSurface::ToolFirst.path(),
    }
}

/// The owner whose held MCP socket this request came on, on a managed vault
/// (FIX 5128): what the socket's upgrade attested, never this request.
pub(super) fn session_owner(
    connection: &Extensions,
    server: &SyncServer,
) -> Option<oneiron::EntityId> {
    connection
        .get::<crate::managed::ManagedOwnerSession>()
        .filter(|_| server.managed_issuer.is_some())
        .map(crate::managed::ManagedOwnerSession::holder)
}

/// The owner a claimed MCP invocation is keyed by, as 32 hex, or empty for
/// none: the one a managed vault's supervisor attested for this request,
/// else the one whose held socket it came on (FIX 5128), who must still be
/// the vault's live owner. Judged before an invocation is claimed or
/// replayed, and again once a claim's wait is over, so a replay is never
/// released to a socket whose owner no longer stands.
pub(super) fn invocation_owner(
    connection: &Extensions,
    server: &SyncServer,
) -> Result<String, McpGatewayError> {
    if let Some(owner) = crate::auth::attested_owner(connection, server) {
        return Ok(owner.to_hex());
    }
    let Some(owner) = session_owner(connection, server) else {
        return Ok(String::new());
    };
    let auth = CoreAuth::for_attested_owner(owner, server).map_err(|_| owner_not_live())?;
    crate::api::scoped_auth::require_live_managed_owner(server, &auth)
        .map_err(|_| owner_not_live())?;
    Ok(owner.to_hex())
}

/// An attested owner's STREAM connection: one per person, derived from him
/// alone under its own prefix, so it never names a connector registration
/// or another person's stream, and does not spell the person's id.
fn owner_stream_connection(owner: oneiron::EntityId) -> StreamConnectionId {
    let key = blake3::derive_key(MCP_OWNER_STREAM_CONTEXT, owner.as_bytes());
    StreamConnectionId(format!("mcp-owner:{}", blake3::Hash::from(key).to_hex()))
}
