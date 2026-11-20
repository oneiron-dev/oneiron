//! A stock cloud client's `/mcp` call on its OAuth access token (FIX 4902 slice C; owner CLOUD
//! AGENTS CONNECT = A, 2026-10-19; ARCH-0028:91 "The OAuth bearer maps to the vault grant at
//! ingress. Clients never hold our slip or keys."), and a git push on the token of a sign-in
//! that also named the vault's `/git` (lead ruling CONTINUE-PUSH-NON-SLIP-SELECTION = B, Sat
//! 21 Nov 04:3x: "only a token that asked for git may push, through the same git_push permission
//! check as today; tokens for ChatGPT or Claude connectors still reach nothing else").
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
//! At `/git/{repo}/...` (smart-HTTP and LFS) the same swap runs on the request's bearer for the
//! `/git` resource: a token whose sign-in named `/git` goes on as its slip, with a fresh holder
//! proof on each of the several requests one push makes, and the git door's gate then judges it
//! as it judges every slip (`core:write`, an unrestricted record scope, a registered principal,
//! and `git_push` admission). A token whose sign-in named `/mcp` alone resolves on no `/git`
//! request, and one that named `/git` alone resolves at no MCP endpoint.
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
use crate::api::oauth_server::{ProtectedResource, resource_identifier, resource_metadata_url};
use crate::cli::McpSurface;
use crate::error::ApiError;
use crate::mcp::McpSurfaceMode;
use crate::server::SyncServer;

/// The kind of the refusal of an OAuth access token that does not resolve, apart from
/// `mcp_auth_required` so its 401 says `invalid_token` (CALLS, FIX 4902: an engine call). It
/// names no reason: an unknown, lapsed, revoked and other resource's token read alike.
const OAUTH_TOKEN_INVALID: &str = "mcp_oauth_token_invalid";

/// The kind of the refusal of a request no cohort admits for want of a credential.
const MCP_AUTH_REQUIRED: &str = "mcp_auth_required";

/// What the refusal of an OAuth access token that does not resolve says, at every door.
const OAUTH_TOKEN_INVALID_TEXT: &str = "the OAuth access token is unknown, lapsed or revoked, or \
     was issued for another resource; refresh it or sign in again";

/// Marks a request whose OAuth access token the binding door swapped for the slip the server
/// holds for it ([`swap_oauth_access_token`]). Only that swap inserts it: no header names it.
#[derive(Clone, Copy)]
struct SwappedOAuthBearer;

/// FIX 4902 slice C's ingress swap, which the binding door runs on each request before it reads
/// any credential (`auth::admit_http_binding`), so its holder-proof admission, its clock
/// classification and the gateway or git door all read the swapped credential. A request to a
/// door of one of this vault's protected resources ([`OAuthDoor`]) whose presented credential
/// is an OAuth access token that resolves on that resource
/// ([`oneiron::Vault::resolve_oauth_access_token`]: its family live and its sign-in naming the
/// resource, its owner agent grant standing, its slip landed) goes on as that token's slip:
/// `Authorization: Bearer <slip>`, a fresh holder proof signed now with the slip's holder key in
/// `x-oneiron-binding`, the MCP connector credential and any machine proof removed (no client
/// holds a key over a slip it never saw), and [`SwappedOAuthBearer`]. Every other request goes
/// on unchanged.
///
/// # Errors
/// The answer for a token that does not resolve: 401 `invalid_token` ([`token_refused`]); a
/// store fault answers 500 (CALLS, FIX 4902: an engine call), so a client keeps a token a fault
/// could not judge. It never goes on.
pub(crate) fn swap_oauth_access_token(
    server: &SyncServer,
    request: &mut Request,
) -> Result<(), Response> {
    let path = request.uri().path();
    let Some(door) = OAuthDoor::of(path) else {
        return Ok(());
    };
    let Some(token) = door
        .presented_credential(request.headers())
        .filter(|credential| credential.starts_with(OAUTH_ACCESS_TOKEN_PREFIX))
    else {
        return Ok(());
    };
    let path = path.to_owned();
    let resolved = match (
        resource_identifier(server, door.resource()),
        server.host_issuer(),
    ) {
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
        Ok(None) => return Err(token_refused(server, door, &path)),
        Err(error) => {
            tracing::warn!(%error, ?door, "an OAuth access token's resolution failed");
            return Err(resolution_failed(door, &path));
        }
    };
    let Some((bearer, binding)) = slip_headers(&access, server.vault().now_recorded_at()) else {
        return Err(resolution_failed(door, &path));
    };
    let headers = request.headers_mut();
    headers.remove(MCP_CREDENTIAL_HEADER);
    headers.remove(MACHINE_PROOF_HEADER);
    headers.insert(AUTHORIZATION, bearer);
    headers.insert(BINDING_HEADER, binding);
    request.extensions_mut().insert(SwappedOAuthBearer);
    Ok(())
}

/// A door that takes an OAuth access token in place of a slip, and the protected resource it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OAuthDoor {
    /// `/mcp` and `/mcp/tool-first`: the one resource `{origin}/mcp`, so one sign-in reaches
    /// either (CALLS, FIX 4902: an engine call).
    Mcp,
    /// `/git/{repo}/...`, the git door a push goes through: `info/refs`, `git-upload-pack`,
    /// `git-receive-pack` and `info/lfs/...`, the resource `{origin}/git`. A lease's door
    /// (`/git/lease/{lease}/{repo}/...`) is none: a lease is its own credential.
    Git,
}

impl OAuthDoor {
    /// The door `path` reaches, if it is one.
    fn of(path: &str) -> Option<Self> {
        if [McpSurface::Primary, McpSurface::ToolFirst]
            .into_iter()
            .any(|surface| surface.path() == path)
        {
            return Some(Self::Mcp);
        }
        git_door(path).then_some(Self::Git)
    }

    /// The protected resource it is.
    const fn resource(self) -> ProtectedResource {
        match self {
            Self::Mcp => ProtectedResource::Mcp,
            Self::Git => ProtectedResource::Git,
        }
    }

    /// The credential a request to it presents: at an MCP endpoint, its MCP connector
    /// credential, else its bearer, the precedence both readers keep; at the git door, its
    /// bearer, the one credential that door reads.
    fn presented_credential(self, headers: &HeaderMap) -> Option<String> {
        match self {
            Self::Mcp => mcp_connector_credential(headers).ok(),
            Self::Git => crate::auth::bearer_token(headers)
                .ok()
                .flatten()
                .map(str::to_owned),
        }
    }
}

/// Whether `path` is the git door's: `/git/{repo}/` and then `info/refs`, `git-upload-pack`,
/// `git-receive-pack` or `info/lfs/...`.
fn git_door(path: &str) -> bool {
    git_door_tail(path).is_some_and(|tail| {
        matches!(tail, "info/refs" | "git-upload-pack" | "git-receive-pack")
            || tail.starts_with("info/lfs/")
    })
}

/// What follows `/git/{repo}/` in `path`, for a `path` that names a repo.
fn git_door_tail(path: &str) -> Option<&str> {
    path.strip_prefix("/git/")
        .and_then(|rest| rest.split_once('/'))
        .and_then(|(repo, tail)| (!repo.is_empty()).then_some(tail))
}

/// The git door's refusal of a request to `path`: on the LFS door (`info/lfs/...`) the
/// envelope that door answers in (`crate::auth::door_refusal`), and on smart HTTP `text` as
/// plain text with `status`, as the git gate answers a request it does not authenticate, since
/// a git client shows that text and reads no JSON.
fn git_door_refusal(path: &str, error: ApiError, status: StatusCode, text: &str) -> Response {
    if git_door_tail(path).is_some_and(|tail| tail.starts_with("info/lfs/")) {
        crate::auth::door_refusal(path, error)
    } else {
        (status, text.to_owned()).into_response()
    }
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

/// The answer to an OAuth access token that does not resolve at `door`: HTTP 401 with
/// `WWW-Authenticate: Bearer error="invalid_token"`, naming the door's resource metadata on a
/// host with an OAuth identity. At an MCP endpoint its body is a JSON-RPC error of no request
/// id, since no body was read; at the git door, plain text on smart HTTP and the LFS door's
/// envelope on `info/lfs/...` ([`git_door_refusal`]). The client refreshes the token or signs
/// in again.
fn token_refused(server: &SyncServer, door: OAuthDoor, path: &str) -> Response {
    let challenge = match resource_metadata_url(server, door.resource()) {
        Some(metadata) => {
            format!("Bearer error=\"invalid_token\", resource_metadata=\"{metadata}\"")
        }
        None => "Bearer error=\"invalid_token\"".to_owned(),
    };
    let response = match door {
        OAuthDoor::Mcp => {
            let refusal =
                McpGatewayError::new(-32001, OAUTH_TOKEN_INVALID, OAUTH_TOKEN_INVALID_TEXT);
            Json(mcp_error_response(Value::Null, refusal)).into_response()
        }
        OAuthDoor::Git => git_door_refusal(
            path,
            ApiError::unauthorized(),
            StatusCode::UNAUTHORIZED,
            OAUTH_TOKEN_INVALID_TEXT,
        ),
    };
    challenged(response, HeaderValue::from_str(&challenge).ok())
}

/// The answer to an OAuth access token a store fault kept the ingress from judging at `door`:
/// HTTP 500, as a JSON-RPC engine error of no request id at an MCP endpoint, and at the git
/// door as [`git_door_refusal`] answers.
fn resolution_failed(door: OAuthDoor, path: &str) -> Response {
    const RETRY: &str = "the OAuth access token could not be judged; retry";
    match door {
        OAuthDoor::Mcp => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(mcp_error_response(
                Value::Null,
                McpGatewayError::new(-32603, "engine_error", RETRY),
            )),
        )
            .into_response(),
        OAuthDoor::Git => git_door_refusal(
            path,
            ApiError::internal_server_error(RETRY),
            StatusCode::INTERNAL_SERVER_ERROR,
            RETRY,
        ),
    }
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
    let metadata = resource_metadata_url(server, ProtectedResource::Mcp)?;
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
