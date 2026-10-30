//! A managed shared vault's member on `/mcp` (FIX 1302 stage 2).
//!
//! His console carries no connector credential, no slip and no owner
//! attestation: his supervisor signed one request for him
//! (`ManagedPersonAction`, verified at managed ingress), or the upgrade of
//! his held MCP socket, each of whose calls names that socket
//! (`ManagedPersonSession`). A `tools/call` of a registered member door
//! (`auth::MANAGED_PERSON_DOORS`, classified by the tool this endpoint
//! registered under that name, never by an argument) is his own act there,
//! as at the facade's member door: a human with core read and write, bound
//! to those doors alone, with no STREAM subscription, never owner grade, and
//! no registration, slip or Grant minted for him. Each door's own person
//! check then judges him, and the engine's roster, role and Grant checks
//! decide. His handshake takes the same caller, and `tools/list` lists him
//! those doors alone. Every other tool of his is refused as before, and a
//! request that carries a credential stays that credential's caller.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::http::header::AUTHORIZATION;
use axum::http::{Extensions, HeaderMap};
use oneiron::context_board::StreamConnectionId;
use serde_json::Value;

use super::actor_dispatch::mcp_request_placement;
use super::{MCP_CREDENTIAL_HEADER, McpCallContext, McpGatewayError};
use crate::auth::{CoreAuth, MANAGED_PERSON_DOORS};
use crate::mcp::{McpConnectorScope, McpEndpointTool, McpResolvedActor, McpSurfaceMode};
use crate::server::SyncServer;

/// The `blake3::derive_key` context of a member's STREAM connection
/// ([`person_stream_connection`]): apart from the owner's and a booking
/// holder's, so his calls never page or drain on theirs.
const MCP_PERSON_STREAM_CONTEXT: &str = "oneiron-server 2026-10 mcp managed-person stream";

/// The caller of a `tools/call` of a member door that carries no credential,
/// by the member his supervisor signed it or its socket for
/// ([`person_context`]). `None` for every other call, which keeps the caller
/// it had.
pub(super) fn tool_caller(
    mode: McpSurfaceMode,
    request_id: &str,
    headers: &HeaderMap,
    connection: &Extensions,
    server: &Arc<SyncServer>,
    params: Option<&Value>,
) -> Option<Result<McpCallContext, McpGatewayError>> {
    let holder = tool_holder(mode, headers, connection, server, params)?;
    Some(person_context(
        mode, request_id, headers, connection, holder, server,
    ))
}

/// The caller of an MCP handshake (`initialize`,
/// `notifications/initialized`, `tools/list`, `oneiron/wakes`) that carries
/// no credential, by the member his supervisor signed it or its socket for,
/// so a client that initializes first reaches the member doors. `None` for
/// every other request.
pub(super) fn handshake_caller(
    mode: McpSurfaceMode,
    request_id: &str,
    headers: &HeaderMap,
    connection: &Extensions,
    server: &Arc<SyncServer>,
) -> Option<Result<McpCallContext, McpGatewayError>> {
    let holder = signed_person(headers, connection, server)?;
    Some(person_context(
        mode, request_id, headers, connection, holder, server,
    ))
}

/// The member a `tools/call` of a member door is his own act for, when it
/// carries no credential of its own ([`signed_person`]). `None` for any
/// other call.
pub(super) fn tool_holder(
    mode: McpSurfaceMode,
    headers: &HeaderMap,
    connection: &Extensions,
    server: &SyncServer,
    params: Option<&Value>,
) -> Option<oneiron::EntityId> {
    person_tool(mode, params)?;
    signed_person(headers, connection, server)
}

/// Whether `actor` is a member's own caller ([`person_context`]).
pub(super) fn is_person_caller(actor: &McpCallContext) -> bool {
    actor
        .auth
        .as_ref()
        .is_some_and(|auth| auth.managed_person().is_some())
}

/// Whether the tool registered as `name` is a member door.
pub(super) fn is_person_door(name: &str) -> bool {
    MANAGED_PERSON_DOORS.contains(&name)
}

/// Whether a member's held MCP socket carries `body`, one JSON-RPC message
/// for the MCP endpoint at `surface`: a handshake method, a `ping` or a
/// notification, which run no verb, or a `tools/call` of a member door that
/// endpoint registered. A batch, a message that is no JSON object, an
/// unknown endpoint and every other method or tool are refused.
pub(crate) fn person_socket_admits(surface: &str, body: &str) -> bool {
    let Ok(Value::Object(message)) = serde_json::from_str::<Value>(body) else {
        return false;
    };
    let Some(method) = message.get("method").and_then(Value::as_str) else {
        return false;
    };
    if method == "tools/call" {
        let mode = if surface == crate::cli::McpSurface::Primary.path() {
            McpSurfaceMode::Primary
        } else if surface == crate::cli::McpSurface::ToolFirst.path() {
            McpSurfaceMode::ToolFirst
        } else {
            return false;
        };
        return person_tool(mode, message.get("params")).is_some();
    }
    matches!(
        method,
        "initialize" | "notifications/initialized" | "tools/list" | "oneiron/wakes" | "ping"
    ) || method.starts_with("notifications/")
}

/// The member a supervisor signed this request for, or the held socket it
/// came on, on a managed vault, when the request carries no credential of
/// its own. `None` for any other request.
fn signed_person(
    headers: &HeaderMap,
    connection: &Extensions,
    server: &SyncServer,
) -> Option<oneiron::EntityId> {
    if server.managed_issuer.is_none()
        || headers.contains_key(MCP_CREDENTIAL_HEADER)
        || headers.contains_key(AUTHORIZATION)
        || crate::auth::carries_caller_slip(headers)
    {
        return None;
    }
    connection
        .get::<crate::managed::ManagedPersonHolder>()
        .map(|holder| holder.0)
        .or_else(|| {
            connection
                .get::<crate::managed::ManagedPersonSession>()
                .map(crate::managed::ManagedPersonSession::holder)
        })
}

/// The member door a `tools/call` names: the tool its `name` resolves to on
/// this endpoint's registered surface, when that tool is one of
/// `auth::MANAGED_PERSON_DOORS`. Nothing in its arguments counts.
fn person_tool(mode: McpSurfaceMode, params: Option<&Value>) -> Option<&'static str> {
    let name = params?.get("name")?.as_str()?;
    let surface = crate::mcp::try_registered_surface(mode).ok()?;
    let McpEndpointTool::Verb(tool) = surface.resolve(name)? else {
        return None;
    };
    MANAGED_PERSON_DOORS
        .into_iter()
        .find(|door| *door == tool.name)
}

/// A member's own call: the person, as a human, bound to the member doors,
/// with no STREAM subscription and no registration behind him. His caller
/// is [`CoreAuth::for_managed_person_call`]'s, placed where this request
/// puts him: never owner grade, so no owner door, owner read key or
/// owner-wide result is his. The request's own placement and session stand.
fn person_context(
    mode: McpSurfaceMode,
    request_id: &str,
    headers: &HeaderMap,
    connection: &Extensions,
    holder: oneiron::EntityId,
    server: &Arc<SyncServer>,
) -> Result<McpCallContext, McpGatewayError> {
    let auth = CoreAuth::for_managed_person_call(holder, headers, connection, server)
        .ok_or_else(person_unsigned)?;
    let (session, room_turn) = mcp_request_placement(headers)?;
    let session_ref = session.map(|session| session.to_hex());
    let scope = McpConnectorScope::vault_wide();
    let actor = McpResolvedActor {
        auth: Some(auth.in_off_record_session(session_ref.as_deref())),
        actor_ref: holder,
        actor_class: oneiron::EdgeActorClass::Human,
        gate_actor_class: oneiron::EdgeActorClass::Human.gate_actor_class(),
        gate_actor_ref: holder.to_hex(),
        stream_connection: person_stream_connection(holder),
        bound_verbs: Some(MANAGED_PERSON_DOORS.into_iter().collect()),
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

/// The refusal of a member's call on a vault no supervisor manages.
fn person_unsigned() -> McpGatewayError {
    McpGatewayError::new(
        -32001,
        "mcp_auth_required",
        "a member's own call needs his supervisor's signature on a managed vault",
    )
}

/// A member's STREAM connection: one per person, derived from him alone
/// under its own prefix, so it never names the owner's stream, a booking
/// holder's, a connector registration or another person's, and does not
/// spell the person's id.
fn person_stream_connection(holder: oneiron::EntityId) -> StreamConnectionId {
    let key = blake3::derive_key(MCP_PERSON_STREAM_CONTEXT, holder.as_bytes());
    StreamConnectionId(format!(
        "mcp-managed-person:{}",
        blake3::Hash::from(key).to_hex()
    ))
}
