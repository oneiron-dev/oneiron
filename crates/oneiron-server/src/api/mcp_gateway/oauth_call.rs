//! A stock cloud client's `/mcp` call on its OAuth access token (FIX 4902 slice C; owner CLOUD
//! AGENTS CONNECT = A, 2026-10-19; ARCH-0028:91 "The OAuth bearer maps to the vault grant at
//! ingress. Clients never hold our slip or keys.").
//!
//! A stock client cannot send `x-oneiron-binding`, so it never holds a slip. It signs in
//! (`api::oauth_server`) and presents its access token as its bearer, or as its MCP connector
//! credential. Such a request is resolved here, before every other cohort, and only here: the
//! token resolves to the vault grant it stands on (`Vault::resolve_oauth_access_token`), or the
//! request is refused, never served as another caller. Its caller is the client's own agent
//! principal (`CoreAuth::for_oauth_access`): an agent with the tier's core scopes, in the one
//! world the grant is bound to or vault-wide, every tool of the endpoint listed and each verb
//! gated by those scopes and the agent's ceiling, as every connector's is. No registration,
//! slip or key is made for it; a long call judges it again by its token family.
//!
//! An anonymous request no cohort admits, on a host with an OAuth identity, answers 401 with
//! `WWW-Authenticate` naming the resource's metadata (RFC 9728 §5.1), and a token that does not
//! resolve answers 401 `invalid_token` (RFC 6750 §3.1), so a client knows to sign in. With no
//! OAuth identity, each answers as before.

use std::sync::Arc;

use axum::http::{Extensions, HeaderMap, HeaderValue, StatusCode, header};
use axum::response::Response;
use oneiron::authority::{OAUTH_ACCESS_TOKEN_PREFIX, OAuthAccess};
use oneiron::claim::CallerLocality;
use oneiron::context_board::StreamConnectionId;

use super::actor_dispatch::{mcp_connector_credential, mcp_request_placement};
use super::{McpCallContext, McpGatewayError};
use crate::auth::{CoreAuth, OAuthAccessInstrument};
use crate::mcp::{McpConnectorScope, McpResolvedActor, McpSurfaceMode};
use crate::server::SyncServer;

/// The `blake3::derive_key` context of an OAuth caller's STREAM connection
/// ([`oauth_stream_connection`]): apart from the owner's, a booking holder's and a member's.
const MCP_OAUTH_STREAM_CONTEXT: &str = "oneiron-server 2026-11 mcp oauth-family stream";

/// The kind of the refusal of an OAuth access token that does not resolve, apart from
/// `mcp_auth_required` so its 401 says `invalid_token` (CALLS, FIX 4902: an engine call). It
/// names no reason: an unknown, lapsed, revoked and other resource's token read alike.
const OAUTH_TOKEN_INVALID: &str = "mcp_oauth_token_invalid";

/// The kind of the refusal of a request no cohort admits for want of a credential.
const MCP_AUTH_REQUIRED: &str = "mcp_auth_required";

/// The caller of one `/mcp` request (a handshake or a `tools/call`) whose presented credential
/// is an OAuth access token: the client's agent, as its token resolves it ([`oauth_context`]),
/// or the refusal of a token that does not. `None` for a request that presents any other
/// credential, or none, which keeps the caller it had.
pub(super) fn caller(
    mode: McpSurfaceMode,
    request_id: &str,
    headers: &HeaderMap,
    connection: &Extensions,
    locality: CallerLocality,
    server: &Arc<SyncServer>,
) -> Option<Result<McpCallContext, McpGatewayError>> {
    let token = mcp_connector_credential(headers)
        .ok()
        .filter(|credential| credential.starts_with(OAUTH_ACCESS_TOKEN_PREFIX))?;
    Some(resolved_caller(
        mode, request_id, headers, connection, locality, server, &token,
    ))
}

/// The caller `token` resolves to on this endpoint's resource now, placed where the request's
/// connection sits. Refused when the host has no OAuth identity or no issuer, and for a token
/// that is unknown, lapsed, revoked, minted for another resource, or whose owner agent grant
/// no longer stands.
fn resolved_caller(
    mode: McpSurfaceMode,
    request_id: &str,
    headers: &HeaderMap,
    connection: &Extensions,
    locality: CallerLocality,
    server: &Arc<SyncServer>,
    token: &str,
) -> Result<McpCallContext, McpGatewayError> {
    let (Some(resource), Some(issuer)) = (oauth_resource(server, mode), server.host_issuer())
    else {
        return Err(token_invalid());
    };
    let access = server
        .vault()
        .resolve_oauth_access_token(issuer, token, &resource, oneiron_vault_contract::now_ts())
        .map_err(|error| super::mcp_engine_error("OAuth access token resolution failed", error))?
        .ok_or_else(token_invalid)?;
    let auth = CoreAuth::for_oauth_access(
        &access,
        &resource,
        locality,
        crate::auth::proved_peer(headers, connection),
    );
    oauth_context(mode, request_id, headers, &access, auth, server)
}

/// The protected resource a call on `mode` reaches (CALLS, FIX 4902: an engine call): both MCP
/// endpoints, `/mcp` and `/mcp/tool-first`, are the one resource `{origin}/mcp`, so one sign-in
/// reaches either and no token reaches anything else. `None` with no OAuth identity.
fn oauth_resource(server: &SyncServer, mode: McpSurfaceMode) -> Option<String> {
    match mode {
        McpSurfaceMode::Primary | McpSurfaceMode::ToolFirst => {
            crate::api::oauth_server::mcp_resource(server)
        }
    }
}

/// The connector scope an OAuth caller acts in (CALLS, FIX 4902: an engine call): the one world
/// its owner agent grant is bound to, every facet of it, when the grant names one; vault-wide
/// when it names none. The owner's allow names no facet.
fn oauth_scope(access: &OAuthAccess) -> McpConnectorScope {
    access
        .world
        .map_or_else(McpConnectorScope::vault_wide, |world| {
            McpConnectorScope::scoped(Some(world), None)
        })
}

/// A stock client's own call: its agent, as an agent, in [`oauth_scope`], with every tool of
/// the endpoint (`bound_verbs` `None`: its scopes and its agent's ceiling gate each verb, as
/// `mcp_call_scope` does every connector's), the STREAM subscriptions that scope admits, and its
/// own STREAM connection ([`oauth_stream_connection`]). `auth` is its caller
/// ([`CoreAuth::for_oauth_access`]): never owner grade, so no owner door, owner read key or
/// owner-wide result is its. The request's own placement and session stand.
fn oauth_context(
    mode: McpSurfaceMode,
    request_id: &str,
    headers: &HeaderMap,
    access: &OAuthAccess,
    auth: CoreAuth,
    server: &Arc<SyncServer>,
) -> Result<McpCallContext, McpGatewayError> {
    let instrument = auth.oauth_access().ok_or_else(token_invalid)?;
    let stream_connection = oauth_stream_connection(instrument);
    let (session, room_turn) = mcp_request_placement(headers)?;
    let session_ref = session.map(|session| session.to_hex());
    let scope = oauth_scope(access);
    let actor = McpResolvedActor {
        auth: Some(auth.in_off_record_session(session_ref.as_deref())),
        actor_ref: access.agent,
        actor_class: access.actor_class,
        gate_actor_class: access.actor_class.gate_actor_class(),
        gate_actor_ref: access.agent.to_hex(),
        stream_connection,
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
        client_surface: None,
        signing_request_transport: None,
    })
}

/// An OAuth caller's STREAM connection: one per instrument, so per sign-in, kept across its
/// refreshes, derived from the instrument's name alone under its own prefix, so it never names
/// another caller's stream or a connector registration, and does not spell the family's id.
fn oauth_stream_connection(instrument: &OAuthAccessInstrument) -> StreamConnectionId {
    let key = blake3::derive_key(MCP_OAUTH_STREAM_CONTEXT, instrument.name().as_bytes());
    StreamConnectionId(format!("mcp-oauth:{}", blake3::Hash::from(key).to_hex()))
}

/// The refusal of an OAuth access token that does not resolve: the client refreshes it or signs
/// in again.
fn token_invalid() -> McpGatewayError {
    McpGatewayError::new(
        -32001,
        OAUTH_TOKEN_INVALID,
        "the OAuth access token is unknown, lapsed or revoked, or was issued for another \
         resource; refresh it or sign in again",
    )
}

/// The `WWW-Authenticate` challenge `error`, this request's refusal, answers with on a host
/// with an OAuth identity: `invalid_token` and the `/mcp` resource's metadata for an OAuth
/// access token that does not resolve; the metadata alone for an anonymous request
/// ([`anonymous`]) no cohort admitted. `None` for every other refusal, and on a host with no
/// OAuth identity: those answer as before.
pub(super) fn auth_challenge(
    server: &SyncServer,
    headers: &HeaderMap,
    connection: &Extensions,
    error: &McpGatewayError,
) -> Option<HeaderValue> {
    let metadata = crate::api::oauth_server::mcp_resource_metadata_url(server)?;
    let challenge = if error.kind == OAUTH_TOKEN_INVALID {
        format!("Bearer error=\"invalid_token\", resource_metadata=\"{metadata}\"")
    } else if error.kind == MCP_AUTH_REQUIRED && anonymous(headers, connection, server) {
        format!("Bearer resource_metadata=\"{metadata}\"")
    } else {
        return None;
    };
    HeaderValue::from_str(&challenge).ok()
}

/// `response` as HTTP 401 with `challenge` in `WWW-Authenticate`, its body unchanged; with no
/// challenge, `response` as it is.
pub(super) fn challenged(mut response: Response, challenge: Option<HeaderValue>) -> Response {
    if let Some(challenge) = challenge {
        *response.status_mut() = StatusCode::UNAUTHORIZED;
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, challenge);
    }
    response
}

/// Whether a request names no caller of any cohort: no MCP connector credential or bearer, no
/// owner its supervisor attested for it or for the held socket it came on, and no member a
/// supervisor signed it or its socket for. Every native cohort's request names one, so its
/// refusals answer as before.
fn anonymous(headers: &HeaderMap, connection: &Extensions, server: &SyncServer) -> bool {
    mcp_connector_credential(headers).is_err()
        && crate::auth::attested_owner(connection, server).is_none()
        && super::owner_call::session_owner(connection, server).is_none()
        && connection
            .get::<crate::managed::ManagedPersonHolder>()
            .is_none()
        && connection
            .get::<crate::managed::ManagedPersonSession>()
            .is_none()
}
