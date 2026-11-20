//! The HTTP side of the vault as its own `/mcp`'s OAuth 2.1 authorization server (FIX 4902 slice
//! B; ARCH-0028 #cloud-agents-connect): the protected-resource metadata (RFC 9728), the
//! authorization-server metadata (RFC 8414), dynamic registration (RFC 7591), the authorize page
//! with the owner's inbox consent, the token endpoint (code with PKCE S256, refresh by rotation,
//! RFC 8707 resource) and revocation (RFC 7009). `oneiron::authority`'s OAuth server holds every
//! row and decision; these doors read the request, fetch a client ID metadata document, and
//! write the reply.
//!
//! The vault's public identity is `oauth_resource_indicator`: its origin is the issuer, and
//! `{origin}/mcp` and `{origin}/git` its two protected resources ([`ProtectedResource`]): a
//! stock connector and `oneiron hosted login` sign in for `/mcp` alone, at the tier asked, and
//! the continue step-up of `oneiron continue --cloud` (and `hosted login --push`) for both at
//! `full`, so only its tokens push through the git door (lead rulings
//! CONTINUE-PUSH-NON-SLIP-SELECTION = B, Sat 21 Nov 04:3x, CONTINUE-PUSH-GIT-TIER = C, 05:4x,
//! and CONTINUE-STEP-UP-MCP-WRITE = A, 06:1x). With none configured, or one that is no https
//! origin,
//! every route here answers 404, as the client metadata documents do. Codes, tokens and the
//! page's poll secret ride only in a body, a header or the client's own redirect, never in this
//! vault's paths, logs or stored rows. The binding door's swap that accepts the tokens at
//! `/mcp` and at `/git/{repo}/...`, and their 401 with `WWW-Authenticate`, are
//! `mcp_gateway::oauth_call`'s (slice C).
//!
//! Registration and authorize are the two doors a stranger can make write: one stores a client,
//! the other records a request, sends the owner an ask, and may fetch and store a client's
//! metadata document. Each is capped per client address and per vault ([`OAuthFloodCaps`]).

mod authorize;
mod client_document;
mod html;
mod metadata;
mod registration;
mod token;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::Router;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use oneiron::authority::{
    OAUTH_AUTHORIZATIONS_PER_HOUR, OAUTH_AUTHORIZATIONS_PER_SOURCE_PER_HOUR,
    OAUTH_REGISTRATIONS_PER_HOUR, OAUTH_REGISTRATIONS_PER_SOURCE_PER_HOUR,
};

use crate::api::FloodCap;
use crate::server::SyncServer;

/// RFC 9728's metadata path, which answers the `/mcp` resource's document.
const PROTECTED_RESOURCE_METADATA_PATH: &str = "/.well-known/oauth-protected-resource";
/// RFC 9728 §3.1's resource-specific metadata path for `/mcp`, which answers the same document.
pub(crate) const PROTECTED_RESOURCE_MCP_METADATA_PATH: &str =
    "/.well-known/oauth-protected-resource/mcp";
/// RFC 9728 §3.1's resource-specific metadata path for `/git`.
pub(crate) const PROTECTED_RESOURCE_GIT_METADATA_PATH: &str =
    "/.well-known/oauth-protected-resource/git";
/// RFC 8414's metadata path for an issuer with no path.
const AUTHORIZATION_SERVER_METADATA_PATH: &str = "/.well-known/oauth-authorization-server";
pub(crate) const AUTHORIZE_PATH: &str = "/oauth/authorize";
const AUTHORIZE_STATUS_PATH: &str = "/oauth/authorize/status";
pub(crate) const TOKEN_PATH: &str = "/oauth/token";
pub(crate) const REGISTER_PATH: &str = "/oauth/register";
pub(crate) const REVOKE_PATH: &str = "/oauth/revoke";

/// The OAuth routes, mounted beside `/oauth/client/*`. The metadata documents are public and
/// cacheable; every other reply is private (`no-store`, `no-referrer`, `nosniff`). The router
/// holds the open doors' flood caps.
pub(super) fn routes() -> Router<Arc<SyncServer>> {
    let private = Router::new()
        .route(REGISTER_PATH, post(registration::register))
        .route(AUTHORIZE_PATH, get(authorize::page))
        .route(AUTHORIZE_STATUS_PATH, get(authorize::status))
        .route(TOKEN_PATH, post(token::token))
        .route(REVOKE_PATH, post(token::revoke))
        .layer(axum::Extension(Arc::new(OAuthFloodCaps::new(
            Instant::now(),
        ))))
        .layer(axum::middleware::from_fn(private_response));
    Router::new()
        .route(
            PROTECTED_RESOURCE_METADATA_PATH,
            get(metadata::protected_resource),
        )
        .route(
            PROTECTED_RESOURCE_MCP_METADATA_PATH,
            get(metadata::protected_resource),
        )
        .route(
            PROTECTED_RESOURCE_GIT_METADATA_PATH,
            get(metadata::git_protected_resource),
        )
        .route(
            AUTHORIZATION_SERVER_METADATA_PATH,
            get(metadata::authorization_server),
        )
        .merge(private)
}

/// The flood caps of the two open doors (FIX 4902): the open inbox's cap ([`FloodCap`]), one per
/// door, counting attempts per client address (`ClientAddress`, the key the inbox and public
/// booking charge: the connection's peer, or the client a configured trusted proxy names) and
/// for the vault as a whole, in hour windows, under the engine's limits
/// (`OAUTH_REGISTRATIONS_PER_SOURCE_PER_HOUR` and the rest). A door asks its cap once it knows
/// it serves OAuth, before it reads the request's body or its client; an attempt past either
/// count gets the cap's typed 429 with `retry-after` until the window turns, and nothing else
/// of it is read. Pre-auth anonymous shedding, the exception the rate law allows (ARCH-0044 C5).
/// The caps live in this process only: a restart forgets them.
struct OAuthFloodCaps {
    registration: FloodCap,
    authorization: FloodCap,
}

impl OAuthFloodCaps {
    fn new(now: Instant) -> Self {
        Self {
            registration: FloodCap::new(
                OAUTH_REGISTRATIONS_PER_SOURCE_PER_HOUR,
                OAUTH_REGISTRATIONS_PER_HOUR,
                now,
            ),
            authorization: FloodCap::new(
                OAUTH_AUTHORIZATIONS_PER_SOURCE_PER_HOUR,
                OAUTH_AUTHORIZATIONS_PER_HOUR,
                now,
            ),
        }
    }

    /// Counts one registration from `source`, or answers its refusal.
    fn shed_registration(&self, source: Option<IpAddr>) -> Option<Response> {
        let shed = self.registration.admit(source, Instant::now()).err()?;
        Some(shed.response(
            "oauth_registration_flood",
            "this vault takes no more app registrations this hour",
        ))
    }

    /// Counts one authorize request from `source`, or answers its refusal.
    fn shed_authorization(&self, source: Option<IpAddr>) -> Option<Response> {
        let shed = self.authorization.admit(source, Instant::now()).err()?;
        Some(shed.response(
            "oauth_authorization_flood",
            "this vault takes no more sign-in requests this hour",
        ))
    }
}

/// One of this vault's two protected resources (RFC 8707, RFC 9728), `{origin}` and its path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProtectedResource {
    /// `/mcp` and `/mcp/tool-first`, the MCP endpoints: one resource, so one sign-in reaches
    /// either.
    Mcp,
    /// `/git/{repo}/...`, the smart-HTTP and LFS door a push goes through.
    Git,
}

impl ProtectedResource {
    /// Every protected resource, in the order a sign-in names them.
    const ALL: [Self; 2] = [Self::Mcp, Self::Git];

    /// Its path under the origin.
    const fn path(self) -> &'static str {
        match self {
            Self::Mcp => "/mcp",
            Self::Git => "/git",
        }
    }

    /// Its own metadata document's path (RFC 9728 §3.1).
    const fn metadata_path(self) -> &'static str {
        match self {
            Self::Mcp => PROTECTED_RESOURCE_MCP_METADATA_PATH,
            Self::Git => PROTECTED_RESOURCE_GIT_METADATA_PATH,
        }
    }

    /// What a sign-in that names it asks to do, as the owner's ask and the consent page say it
    /// (CONTINUE-STEP-UP-MCP-WRITE = A): `None` for `/mcp`, whose tier says it. The one client
    /// that names `/git` is `oneiron continue --cloud`'s step-up.
    const fn purpose(self) -> Option<&'static str> {
        match self {
            Self::Mcp => None,
            Self::Git => Some(GIT_SIGN_IN_PURPOSE),
        }
    }
}

/// What a sign-in naming `/git` asks to do, in the owner's ask (CONTINUE-STEP-UP-MCP-WRITE = A,
/// its wording as ruled).
const GIT_SIGN_IN_PURPOSE: &str =
    "continue this session in your hosted vault: land its log, push its code and start it there";

/// This vault's public OAuth identity, from `oauth_resource_indicator`.
pub(super) struct OAuthIdentity {
    origin: String,
}

impl OAuthIdentity {
    /// The identity the server's configuration names; `None` serves no OAuth route.
    fn of(server: &SyncServer) -> Option<Self> {
        oauth_origin(server.config.oauth_resource_indicator.as_deref())
            .map(|origin| Self { origin })
    }

    /// The issuer identifier: the origin itself (RFC 8414 §2, RFC 9207).
    fn issuer(&self) -> &str {
        &self.origin
    }

    /// The protected resource `resource`'s identifier, `{origin}/mcp` or `{origin}/git` (RFC
    /// 8707, RFC 9728).
    fn resource(&self, resource: ProtectedResource) -> String {
        format!("{}{}", self.origin, resource.path())
    }

    /// The protected resource `identifier` names exactly, if it names one of this vault's.
    fn named_resource(&self, identifier: &str) -> Option<ProtectedResource> {
        ProtectedResource::ALL
            .into_iter()
            .find(|resource| self.resource(*resource) == identifier)
    }

    /// One endpoint's absolute URL.
    fn endpoint(&self, path: &str) -> String {
        format!("{}{path}", self.origin)
    }
}

/// The identifier of `resource`, `{origin}/mcp` or `{origin}/git`, that an access token is
/// resolved on at its door (FIX 4902 slice C). `None` with no OAuth identity configured.
pub(in crate::api) fn resource_identifier(
    server: &SyncServer,
    resource: ProtectedResource,
) -> Option<String> {
    OAuthIdentity::of(server).map(|identity| identity.resource(resource))
}

/// `resource`'s own metadata document (RFC 9728 §3.1), as a 401 from its door names it in
/// `WWW-Authenticate` (RFC 9728 §5.1, FIX 4902 slice C). `None` with no OAuth identity.
pub(in crate::api) fn resource_metadata_url(
    server: &SyncServer,
    resource: ProtectedResource,
) -> Option<String> {
    OAuthIdentity::of(server).map(|identity| identity.endpoint(resource.metadata_path()))
}

/// The OAuth origin `configured` names (CALLS, FIX 4902: an engine call): an https URL with a
/// host and no user info, query, fragment or path past `/`, as its origin, with no trailing
/// slash, as `public_origin` spells Slack's. An indicator with a path names none, since RFC 8414
/// would then place the metadata under a path this router does not serve.
fn oauth_origin(configured: Option<&str>) -> Option<String> {
    let url = reqwest::Url::parse(configured?.trim()).ok()?;
    let origin = url.scheme() == "https"
        && url.host_str().is_some_and(|host| !host.is_empty())
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && url.path() == "/";
    origin.then(|| url.origin().ascii_serialization())
}

/// A bare 404, as every route answers with no OAuth identity configured.
fn not_found() -> Response {
    StatusCode::NOT_FOUND.into_response()
}

/// An OAuth error body: `{"error": code}` (RFC 6749 §5.2, RFC 7591 §3.2.2).
fn oauth_error(status: StatusCode, code: &'static str) -> Response {
    (status, axum::Json(serde_json::json!({ "error": code }))).into_response()
}

/// The wall clock the OAuth rows' lifetimes are read against (Unix seconds).
fn now() -> u64 {
    oneiron_vault_contract::now_ts()
}

/// Every private OAuth reply is never cached, never sent on as a referrer, and never sniffed.
async fn private_response(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}
