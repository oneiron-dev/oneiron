//! A managed vault's attested holder the vault no longer records as its
//! live owner, calling a booking tool on `/mcp` (FIX 5327, Engine ruling (a)
//! 10-20).
//!
//! His console carries no connector credential: its supervisor attested him
//! for one request (`ManagedOwnerAction`), or for the upgrade of his held
//! socket (`ManagedOwnerSession`). While the vault records him as its live
//! owner every call of his is the owner's own (`owner_call`). Once it does
//! not, a call of a registered booking tool (one of the generated booking
//! verbs among `BOOKING_PAYER_DOORS`, classified by the tool this endpoint
//! registered under that name, never by an argument) is still his, as a
//! booking caller and nothing more: the five booking verbs alone, no STREAM
//! subscription, core read and write only, no owner grade, no registration,
//! slip or Grant minted for him. The booking door judges whom he pays as and
//! answers through the public booking authority. His handshake takes the
//! same caller (FIX 5934, Engine ruling 10-20 08:4x), so a client that
//! initializes first reaches those tools: `initialize`,
//! `notifications/initialized`, `tools/list` (listing those five tools
//! alone) and `oneiron/wakes` (whose instance can reach no subscription).
//! Every other method and tool of his is refused as before, and a request
//! that carries a credential stays that credential's caller.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::http::header::AUTHORIZATION;
use axum::http::{Extensions, HeaderMap};
use oneiron::context_board::StreamConnectionId;
use serde_json::Value;

use super::actor_dispatch::mcp_request_placement;
use super::{MCP_CREDENTIAL_HEADER, McpCallContext, McpGatewayError};
use crate::auth::CoreAuth;
use crate::mcp::{McpConnectorScope, McpEndpointTool, McpResolvedActor, McpSurfaceMode};
use crate::server::SyncServer;

/// The `blake3::derive_key` context of a stale owner sign-in's booking
/// STREAM connection ([`booking_stream_connection`]): apart from the live
/// owner's, so his booking calls never page or drain on it.
const MCP_BOOKING_HOLDER_STREAM_CONTEXT: &str =
    "oneiron-server 2026-10 mcp stale-owner booking stream";

/// The caller of one `tools/call`: for a booking tool called with no
/// credential by an attested holder the vault no longer records as its live
/// owner, that holder as a booking caller ([`booking_context`]); for a
/// member door called with no credential by a member his supervisor signed
/// it for, that member (FIX 1302, `person_call`); for every other call, the
/// caller `owner_call::resolve_mcp_caller` resolves.
pub(super) async fn resolve_tool_caller(
    mode: McpSurfaceMode,
    request_id: &str,
    headers: &HeaderMap,
    connection: &Extensions,
    locality: oneiron::claim::CallerLocality,
    server: &Arc<SyncServer>,
    params: Option<&Value>,
) -> Result<McpCallContext, McpGatewayError> {
    if let Some(person) =
        super::person_call::tool_caller(mode, request_id, headers, connection, server, params)
    {
        return person;
    }
    let holder = booking_holder(mode, headers, connection, server, params);
    resolve_holder_or_caller(
        mode, request_id, headers, connection, locality, server, holder,
    )
    .await
}

/// The caller of an MCP handshake (FIX 5934, Engine ruling 10-20 08:4x):
/// `initialize`, `notifications/initialized`, `tools/list` and
/// `oneiron/wakes`. An attested holder with no credential the vault no
/// longer records as its live owner is his booking caller, as for a booking
/// tool call ([`booking_context`]), so a client that initializes first
/// reaches the booking tools; a member his supervisor signed it for, that
/// member (FIX 1302, `person_call`); every other caller as
/// `owner_call::resolve_mcp_caller` resolves it.
pub(super) async fn resolve_handshake_caller(
    mode: McpSurfaceMode,
    request_id: &str,
    headers: &HeaderMap,
    connection: &Extensions,
    locality: oneiron::claim::CallerLocality,
    server: &Arc<SyncServer>,
) -> Result<McpCallContext, McpGatewayError> {
    if let Some(person) =
        super::person_call::handshake_caller(mode, request_id, headers, connection, server)
    {
        return person;
    }
    let holder = uncredentialed_holder(headers, connection, server);
    resolve_holder_or_caller(
        mode, request_id, headers, connection, locality, server, holder,
    )
    .await
}

/// What `tools/list` lists for `actor` (FIX 5934): the endpoint's frozen
/// listing, the same bytes for every caller, except a stale owner sign-in's
/// booking caller, who is listed only the booking tools he may call, and a
/// member's own caller, who is listed only the member doors (FIX 1302).
pub(super) fn tools_listing(
    server: &SyncServer,
    mode: McpSurfaceMode,
    actor: &McpCallContext,
) -> Result<Value, McpGatewayError> {
    let listing = server
        .mcp_surface(mode)
        .map_err(super::admission::mcp_surface_unavailable)?
        .listing()
        .clone();
    let listed: fn(&str) -> bool = if super::person_call::is_person_caller(actor) {
        super::person_call::is_person_door
    } else if actor
        .auth
        .as_ref()
        .is_some_and(CoreAuth::is_attested_booking_holder)
    {
        |name| crate::api::booking::booking_payer_verbs().any(|verb| verb == name)
    } else {
        return Ok(listing);
    };
    let Value::Array(tools) = listing else {
        return Ok(Value::Array(Vec::new()));
    };
    Ok(Value::Array(
        tools
            .into_iter()
            .filter(|tool| tool.get("name").and_then(Value::as_str).is_some_and(listed))
            .collect(),
    ))
}

/// `holder`'s booking caller ([`booking_context`]) while the vault no
/// longer records him as its live owner; else, and with no holder, the
/// caller `owner_call::resolve_mcp_caller` resolves.
async fn resolve_holder_or_caller(
    mode: McpSurfaceMode,
    request_id: &str,
    headers: &HeaderMap,
    connection: &Extensions,
    locality: oneiron::claim::CallerLocality,
    server: &Arc<SyncServer>,
    holder: Option<oneiron::EntityId>,
) -> Result<McpCallContext, McpGatewayError> {
    if let Some(holder) = holder
        && let Some(auth) = CoreAuth::for_placed_booking_holder(
            holder,
            headers,
            connection,
            super::owner_call::owner_path(mode),
            server,
        )
    {
        return booking_context(mode, request_id, headers, holder, auth, server);
    }
    super::owner_call::resolve_mcp_caller(mode, request_id, headers, connection, locality, server)
        .await
}

/// The owner a claimed `tools/call` invocation is keyed by: for a booking
/// tool called with no credential by an attested holder, that holder, live
/// owner or not, whose call books as `resolve_tool_caller` resolves it; for
/// a member door called with no credential by a member his supervisor
/// signed it for, that member (FIX 1302); for every other call, as
/// `owner_call::invocation_owner` keys and judges it.
pub(super) fn invocation_owner(
    mode: McpSurfaceMode,
    headers: &HeaderMap,
    connection: &Extensions,
    server: &SyncServer,
    params: Option<&Value>,
) -> Result<String, McpGatewayError> {
    if let Some(holder) =
        super::person_call::tool_holder(mode, headers, connection, server, params)
    {
        return Ok(holder.to_hex());
    }
    if let Some(holder) = booking_holder(mode, headers, connection, server, params) {
        return Ok(holder.to_hex());
    }
    super::owner_call::invocation_owner(connection, server)
}

/// The attested holder of a booking tool call that carries no credential of
/// its own ([`uncredentialed_holder`]). `None` for any other call.
fn booking_holder(
    mode: McpSurfaceMode,
    headers: &HeaderMap,
    connection: &Extensions,
    server: &SyncServer,
    params: Option<&Value>,
) -> Option<oneiron::EntityId> {
    booking_tool(mode, params)?;
    uncredentialed_holder(headers, connection, server)
}

/// The attested holder of a request that carries no credential of its own:
/// the one a managed vault's supervisor attested for this request, else the
/// one whose held socket it came on. `None` for any other request.
fn uncredentialed_holder(
    headers: &HeaderMap,
    connection: &Extensions,
    server: &SyncServer,
) -> Option<oneiron::EntityId> {
    if headers.contains_key(MCP_CREDENTIAL_HEADER) || headers.contains_key(AUTHORIZATION) {
        return None;
    }
    crate::auth::attested_owner(connection, server)
        .or_else(|| super::owner_call::session_owner(connection, server))
}

/// The booking verb a `tools/call` names: the tool its `name` resolves to on
/// this endpoint's registered surface, when that tool is one of the
/// generated booking verbs. Nothing in its arguments counts.
fn booking_tool(mode: McpSurfaceMode, params: Option<&Value>) -> Option<&'static str> {
    let name = params?.get("name")?.as_str()?;
    let surface = crate::mcp::try_registered_surface(mode).ok()?;
    let McpEndpointTool::Verb(tool) = surface.resolve(name)? else {
        return None;
    };
    crate::api::booking::booking_payer_verbs().find(|verb| *verb == tool.name)
}

/// A stale owner sign-in's booking call: the person, as a human, bound to
/// the five booking verbs, with no STREAM subscription and no registration
/// behind him. `auth` is his booking caller
/// ([`CoreAuth::for_attested_booking_holder`]), placed where this request
/// puts him: never owner grade, so no owner door, owner read key or
/// owner-wide result is his. The request's own placement and session stand.
fn booking_context(
    mode: McpSurfaceMode,
    request_id: &str,
    headers: &HeaderMap,
    holder: oneiron::EntityId,
    auth: CoreAuth,
    server: &Arc<SyncServer>,
) -> Result<McpCallContext, McpGatewayError> {
    let (session, room_turn) = mcp_request_placement(headers)?;
    let session_ref = session.map(|session| session.to_hex());
    let scope = McpConnectorScope::vault_wide();
    let actor = McpResolvedActor {
        auth: Some(auth.in_off_record_session(session_ref.as_deref())),
        actor_ref: holder,
        actor_class: oneiron::EdgeActorClass::Human,
        gate_actor_class: oneiron::EdgeActorClass::Human.gate_actor_class(),
        gate_actor_ref: holder.to_hex(),
        stream_connection: booking_stream_connection(holder),
        bound_verbs: Some(crate::api::booking::booking_payer_verbs().collect()),
        subscription_ceiling: BTreeSet::new(),
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
        client_surface: None,
    })
}

/// A stale owner sign-in's booking STREAM connection: one per person,
/// derived from him alone under its own prefix, so it never names the live
/// owner's stream, a connector registration or another person's, and does
/// not spell the person's id.
fn booking_stream_connection(holder: oneiron::EntityId) -> StreamConnectionId {
    let key = blake3::derive_key(MCP_BOOKING_HOLDER_STREAM_CONTEXT, holder.as_bytes());
    StreamConnectionId(format!(
        "mcp-booking-holder:{}",
        blake3::Hash::from(key).to_hex()
    ))
}
