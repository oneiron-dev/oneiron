//! A stock cloud client's `/mcp` call on its OAuth access token (FIX 4902 slice C; owner CLOUD
//! AGENTS CONNECT = A, 2026-10-19; ARCH-0028:91 "The OAuth bearer maps to the vault grant at
//! ingress. Clients never hold our slip or keys.").
//!
//! A stock client cannot send `x-oneiron-binding`, so it never holds a slip. It signs in
//! (`api::oauth_server`) and presents its access token as its bearer, or as its MCP connector
//! credential. For each access token the server holds a native capability slip of the client's
//! agent, minted beside the token through the paired path (`oneiron::authority::oauth_server`'s
//! `access_slips`). The binding door swaps the token for that slip first of all
//! ([`swap_oauth_access_token`]): `Authorization: Bearer <slip>` and a fresh holder proof the
//! server signs with the slip's holder key, so the door spends that proof once, as every slip's,
//! and the gateway resolves the request as the slip's registered connector ([`caller`]) and as
//! no other cohort. Its tools, scopes, ceiling, reads, code runs and hook asks are then every
//! connector's. A token that does not resolve is refused there, never served as another caller.
//!
//! A token that does not resolve answers 401 `invalid_token` (RFC 6750 §3.1), and an anonymous
//! request no cohort admits, on a host with an OAuth identity, answers 401 with
//! `WWW-Authenticate` naming the resource's metadata (RFC 9728 §5.1), so a client knows to
//! refresh or sign in. With no OAuth identity, an anonymous request answers as before.

use std::sync::Arc;

use axum::Json;
use axum::extract::Request;
use axum::http::header::AUTHORIZATION;
use axum::http::{Extensions, HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use oneiron::authority::{MACHINE_PROOF_HEADER, OAUTH_ACCESS_TOKEN_PREFIX, OAuthAccess};
use oneiron::claim::CallerLocality;
use oneiron_vault_contract::{BINDING_HEADER, MCP_CREDENTIAL_HEADER};
use serde_json::Value;

use super::actor_dispatch::mcp_connector_credential;
use super::{McpCallContext, McpGatewayError, mcp_error_response, resolve_mcp_gateway_actor};
use crate::cli::McpSurface;
use crate::mcp::McpSurfaceMode;
use crate::server::SyncServer;

/// The kind of the refusal of an OAuth access token that does not resolve, apart from
/// `mcp_auth_required` so its 401 says `invalid_token` (CALLS, FIX 4902: an engine call). It
/// names no reason: an unknown, lapsed, revoked and other resource's token read alike.
const OAUTH_TOKEN_INVALID: &str = "mcp_oauth_token_invalid";

/// The kind of the refusal of a request no cohort admits for want of a credential.
const MCP_AUTH_REQUIRED: &str = "mcp_auth_required";

/// Marks a request whose OAuth access token the binding door swapped for the slip the server
/// holds for it ([`swap_oauth_access_token`]). Only that swap inserts it: no header names it.
#[derive(Clone, Copy)]
struct SwappedOAuthBearer;

/// FIX 4902 slice C's ingress swap, which the binding door runs on each request before it reads
/// any credential (`auth::admit_http_binding`), so its holder-proof admission, its clock
/// classification and the gateway all read the swapped credential. A request to either MCP
/// endpoint whose presented credential (its MCP connector credential, else its bearer, the
/// precedence both readers keep) is an OAuth access token that resolves on this vault's `/mcp`
/// resource ([`oneiron::Vault::resolve_oauth_access_token`]: its family live, its owner agent
/// grant standing, its slip landed) goes on as that token's slip: `Authorization: Bearer <slip>`,
/// a fresh holder proof signed now with the slip's holder key in `x-oneiron-binding`, the MCP
/// connector credential and any machine proof removed (no client holds a key over a slip it
/// never saw), and [`SwappedOAuthBearer`]. Every other request goes on unchanged.
///
/// # Errors
/// The answer for a token that does not resolve: 401 `invalid_token` ([`token_refused`]); a
/// store fault answers 500 (CALLS, FIX 4902: an engine call), so a client keeps a token a fault
/// could not judge. It never goes on.
pub(crate) fn swap_oauth_access_token(
    server: &SyncServer,
    request: &mut Request,
) -> Result<(), Response> {
    if !mcp_endpoint(request.uri().path()) {
        return Ok(());
    }
    let Some(token) = mcp_connector_credential(request.headers())
        .ok()
        .filter(|credential| credential.starts_with(OAUTH_ACCESS_TOKEN_PREFIX))
    else {
        return Ok(());
    };
    let resolved = match (oauth_resource(server), server.host_issuer()) {
        (Some(resource), Some(issuer)) => server.vault().resolve_oauth_access_token(
            issuer,
            &token,
            &resource,
            oneiron_vault_contract::now_ts(),
        ),
        _ => Ok(None),
    };
    let access = match resolved {
        Ok(Some(access)) => access,
        Ok(None) => return Err(token_refused(server)),
        Err(error) => {
            tracing::warn!(%error, "an OAuth access token's resolution at /mcp failed");
            return Err(resolution_failed());
        }
    };
    let Some((bearer, binding)) = slip_headers(&access, server.vault().now_recorded_at()) else {
        return Err(resolution_failed());
    };
    let headers = request.headers_mut();
    headers.remove(MCP_CREDENTIAL_HEADER);
    headers.remove(MACHINE_PROOF_HEADER);
    headers.insert(AUTHORIZATION, bearer);
    headers.insert(BINDING_HEADER, binding);
    request.extensions_mut().insert(SwappedOAuthBearer);
    Ok(())
}

/// Whether `path` is one of the MCP endpoints, `/mcp` and `/mcp/tool-first`.
fn mcp_endpoint(path: &str) -> bool {
    [McpSurface::Primary, McpSurface::ToolFirst]
        .into_iter()
        .any(|surface| surface.path() == path)
}

/// The protected resource a request to either MCP endpoint reaches (CALLS, FIX 4902: an engine
/// call): `/mcp` and `/mcp/tool-first` are the one resource `{origin}/mcp`, so one sign-in
/// reaches either and no token reaches anything else. `None` on a host with no OAuth identity,
/// where no token resolves.
fn oauth_resource(server: &SyncServer) -> Option<String> {
    crate::api::oauth_server::mcp_resource(server)
}

/// The bearer and the binding header `access`'s slip goes on with: the slip's token, and a
/// fresh holder proof signed at `timestamp`, each marked sensitive. `None` when either cannot
/// be written.
fn slip_headers(access: &OAuthAccess, timestamp: u64) -> Option<(HeaderValue, HeaderValue)> {
    let token = access.slip.to_token().ok()?;
    let proof = access.holder_proof(timestamp).ok()?;
    let mut bearer = HeaderValue::from_str(&format!("Bearer {token}")).ok()?;
    bearer.set_sensitive(true);
    let mut binding = HeaderValue::from_str(&proof.to_string()).ok()?;
    binding.set_sensitive(true);
    Some((bearer, binding))
}

/// The caller of one `/mcp` request (a handshake or a `tools/call`) whose OAuth access token
/// the binding door swapped ([`swap_oauth_access_token`]): the registered connector of the slip it
/// now carries, as every connector's call resolves it (`resolve_mcp_gateway_actor`), holding the
/// holder proof the door admitted, and nothing else: no booking, member or owner cohort reads
/// it. `None` for every other request, which keeps the caller it had.
pub(super) async fn caller(
    mode: McpSurfaceMode,
    request_id: &str,
    headers: &HeaderMap,
    connection: &Extensions,
    locality: CallerLocality,
    server: &Arc<SyncServer>,
) -> Option<Result<McpCallContext, McpGatewayError>> {
    if !swapped(connection) {
        return None;
    }
    Some(
        resolve_mcp_gateway_actor(mode, request_id, headers, connection, locality, server)
            .await
            .map(|context| super::owner_call::with_admitted_proof(context, connection)),
    )
}

/// Whether the binding door swapped this request's OAuth access token for its slip.
pub(super) fn swapped(connection: &Extensions) -> bool {
    connection.get::<SwappedOAuthBearer>().is_some()
}

/// The answer to an OAuth access token that does not resolve: HTTP 401 with
/// `WWW-Authenticate: Bearer error="invalid_token"`, naming the `/mcp` resource's metadata on a
/// host with an OAuth identity, and a JSON-RPC error of no request id, since no body was read.
/// The client refreshes the token or signs in again.
fn token_refused(server: &SyncServer) -> Response {
    let challenge = match crate::api::oauth_server::mcp_resource_metadata_url(server) {
        Some(metadata) => {
            format!("Bearer error=\"invalid_token\", resource_metadata=\"{metadata}\"")
        }
        None => "Bearer error=\"invalid_token\"".to_owned(),
    };
    let refusal = McpGatewayError::new(
        -32001,
        OAUTH_TOKEN_INVALID,
        "the OAuth access token is unknown, lapsed or revoked, or was issued for another \
         resource; refresh it or sign in again",
    );
    let response = Json(mcp_error_response(Value::Null, refusal)).into_response();
    challenged(response, HeaderValue::from_str(&challenge).ok())
}

/// The answer to an OAuth access token a store fault kept the ingress from judging: HTTP 500
/// and a JSON-RPC engine error of no request id.
fn resolution_failed() -> Response {
    let refusal = McpGatewayError::new(
        -32603,
        "engine_error",
        "the OAuth access token could not be judged; retry",
    );
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(mcp_error_response(Value::Null, refusal)),
    )
        .into_response()
}

/// The `WWW-Authenticate` challenge `error`, this request's refusal, answers with on a host
/// with an OAuth identity: the `/mcp` resource's metadata for an anonymous request
/// ([`anonymous`]) no cohort admitted. `None` for every other refusal, and on a host with no
/// OAuth identity: those answer as before.
pub(super) fn auth_challenge(
    server: &SyncServer,
    headers: &HeaderMap,
    connection: &Extensions,
    error: &McpGatewayError,
) -> Option<HeaderValue> {
    if error.kind != MCP_AUTH_REQUIRED || !anonymous(headers, connection, server) {
        return None;
    }
    let metadata = crate::api::oauth_server::mcp_resource_metadata_url(server)?;
    HeaderValue::from_str(&format!("Bearer resource_metadata=\"{metadata}\"")).ok()
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
