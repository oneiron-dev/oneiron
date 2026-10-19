//! A managed vault's console owner on `/mcp` (WILL-PLAN L14 row 01).
//!
//! The owner's console carries no connector credential: its supervisor
//! attests the vault's owner for one request (`ManagedOwnerAction`, verified
//! at managed ingress). Such a request is the owner's own call, never a
//! paired agent's or a slip's. A request that carries a credential stays
//! that credential's caller, with its registration, scope and Grant.

use std::sync::Arc;

use axum::http::header::AUTHORIZATION;
use axum::http::{Extensions, HeaderMap};
use oneiron::context_board::StreamConnectionId;

use super::actor_dispatch::mcp_request_placement;
use super::{MCP_CREDENTIAL_HEADER, McpCallContext, McpGatewayError, resolve_mcp_gateway_actor};
use crate::mcp::{McpConnectorScope, McpResolvedActor, McpSurfaceMode};
use crate::server::SyncServer;

/// The route a managed vault's supervisor attests an owner's MCP call on.
const MCP_OWNER_PATH: &str = "/mcp";

/// The `blake3::derive_key` context of an attested owner's STREAM
/// connection ([`owner_stream_connection`]).
const MCP_OWNER_STREAM_CONTEXT: &str = "oneiron-server 2026-10 mcp managed-owner stream";

/// The caller of one `/mcp` request. A request that carries no connector
/// credential of its own, on a managed vault whose supervisor attested its
/// owner for it, is that owner's own call ([`managed_owner_context`]). Any
/// other request is the registered connector its credential names
/// ([`resolve_mcp_gateway_actor`]); beside an attestation that credential
/// stays the caller, with its own bounds, and must name the attested person.
pub(crate) async fn resolve_mcp_caller(
    mode: McpSurfaceMode,
    request_id: &str,
    headers: &HeaderMap,
    connection: &Extensions,
    locality: oneiron::claim::CallerLocality,
    server: &Arc<SyncServer>,
) -> Result<McpCallContext, McpGatewayError> {
    let Some(owner) = crate::auth::attested_owner(connection, server) else {
        return resolve_mcp_gateway_actor(mode, request_id, headers, locality, server).await;
    };
    if !headers.contains_key(MCP_CREDENTIAL_HEADER) && !headers.contains_key(AUTHORIZATION) {
        return managed_owner_context(mode, request_id, headers, connection, owner, server);
    }
    let context = resolve_mcp_gateway_actor(mode, request_id, headers, locality, server).await?;
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

/// A managed vault's attested owner's own `/mcp` call: the person, as a
/// human, vault-wide, while the vault records him as its live owner. Its
/// auth is the request's one caller
/// ([`CoreAuth::for_managed_request`](crate::auth::CoreAuth::for_managed_request)),
/// so his reads run under his own key held to this request's owner proof,
/// and each verb's own owner and Grant checks judge him. No registration
/// stands behind it: no connector record, slip or bound-verb ceiling is made
/// for him, and a call settlement runs again finds none. Pagination, wakes
/// and code runs key on his own STREAM connection
/// ([`owner_stream_connection`]).
fn managed_owner_context(
    mode: McpSurfaceMode,
    request_id: &str,
    headers: &HeaderMap,
    connection: &Extensions,
    owner: oneiron::EntityId,
    server: &Arc<SyncServer>,
) -> Result<McpCallContext, McpGatewayError> {
    let refused = || {
        McpGatewayError::new(
            -32001,
            "mcp_auth_required",
            "the attested owner is not this vault's live owner",
        )
    };
    let auth =
        crate::auth::CoreAuth::for_managed_request(headers, connection, MCP_OWNER_PATH, server)
            .and_then(Result::ok)
            .filter(|auth| auth.managed_owner() == Some(owner))
            .ok_or_else(refused)?;
    crate::api::scoped_auth::require_live_managed_owner(server, &auth).map_err(|_| refused())?;
    let (session, room_turn) = mcp_request_placement(headers)?;
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

/// An attested owner's STREAM connection: one per person, derived from him
/// alone under its own prefix, so it never names a connector registration
/// or another person's stream, and does not spell the person's id.
fn owner_stream_connection(owner: oneiron::EntityId) -> StreamConnectionId {
    let key = blake3::derive_key(MCP_OWNER_STREAM_CONTEXT, owner.as_bytes());
    StreamConnectionId(format!("mcp-owner:{}", blake3::Hash::from(key).to_hex()))
}
