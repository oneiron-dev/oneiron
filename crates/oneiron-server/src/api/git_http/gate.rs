//! Authentication gate and service canonicalization for Git smart-HTTP.

// ---------------------------------------------------------------------------
// The auth gate
// ---------------------------------------------------------------------------

use super::routes::GitService;
use crate::auth::CoreAuth;
use crate::auth::RevokedTokenJtis;
use crate::config::SyncServerConfig;
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::http::header::WWW_AUTHENTICATE;
use axum::response::IntoResponse;
use axum::response::Response;

/// The bearer challenge an unauthenticated smart-HTTP request receives.
pub(super) const GIT_HTTP_CHALLENGE: &str = "Bearer realm=\"oneiron-origin\"";

/// Authenticates one smart-HTTP request.
///
/// Split from the handlers so the gate is testable as itself: the dev hatch,
/// the scope check, and the registered-principal demand are one function with
/// no transport around them.
pub(super) fn authenticate(
    headers: &HeaderMap,
    config: &SyncServerConfig,
    revoked: &dyn RevokedTokenJtis,
    service: GitService,
) -> Result<CoreAuth, Box<Response>> {
    let auth =
        CoreAuth::from_headers(headers, config, revoked).map_err(|_| Box::new(challenge()))?;
    auth.require(service.scope())
        .map_err(|error| Box::new(text_response(error.status(), "insufficient scope")))?;
    if service == GitService::ReceivePack {
        // RC4. A hatch-only identity and a bare trust-root secret both reach
        // here with every scope and no principal_ref; neither is a registered
        // actor, so neither may push — including on 127.0.0.1.
        auth.require_registered_principal().map_err(|error| {
            Box::new(text_response(
                error.status(),
                "receive-pack requires a registered principal_ref",
            ))
        })?;
    }
    Ok(auth)
}

fn challenge() -> Response {
    let mut response = text_response(StatusCode::UNAUTHORIZED, "authentication required");
    if let Ok(value) = GIT_HTTP_CHALLENGE.parse() {
        response.headers_mut().insert(WWW_AUTHENTICATE, value);
    }
    response
}

/// The reflog identity of anything this request lands: the registered
/// principal when there is one, and never a fabricated stand-in.
pub(super) fn remote_user(auth: &CoreAuth) -> Option<String> {
    auth.principal_ref().map(str::to_owned)
}

/// Why an `info/refs` query names no service this origin will advertise.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ServiceRefusal {
    /// No `service=` at all: a dumb-protocol probe.
    Missing,
    /// More than one `service=`. The value is ambiguous, so there is no
    /// question to answer.
    Ambiguous,
    /// A `service=` this origin does not serve.
    Unsupported,
}

impl ServiceRefusal {
    pub(super) fn response(self) -> Response {
        match self {
            // Only the smart protocol is served. A dumb-protocol probe is
            // refused here rather than answered with a directory listing.
            Self::Missing => text_response(
                StatusCode::BAD_REQUEST,
                "oneiron origin serves the smart protocol only: name one service=",
            ),
            Self::Ambiguous => text_response(
                StatusCode::BAD_REQUEST,
                "info/refs accepts exactly one service= parameter",
            ),
            Self::Unsupported => text_response(
                StatusCode::FORBIDDEN,
                "oneiron origin serves git-upload-pack and git-receive-pack only",
            ),
        }
    }
}

/// The one service an `info/refs` query names, or why it names none.
///
/// Exactly one is the whole rule. `git http-backend` reads the LAST `service=`
/// in the query string it is handed, so a gate that read the first would decide
/// about one service while the backend advertised another — a `core:read`
/// bearer could ask for `git-upload-pack` and be handed the `git-receive-pack`
/// advertisement. A query carrying zero or several is refused HERE, before the
/// auth gate and before any child exists, and the value this returns is the
/// only spelling the backend is ever given.
pub(super) fn advertised_service(query: &str) -> Result<GitService, ServiceRefusal> {
    let mut named = query
        .split('&')
        .filter_map(|pair| pair.strip_prefix("service="));
    let value = named.next().ok_or(ServiceRefusal::Missing)?;
    if named.next().is_some() {
        return Err(ServiceRefusal::Ambiguous);
    }
    GitService::parse(value).ok_or(ServiceRefusal::Unsupported)
}

/// `demo` and `demo.git` name the same served repository; the `.git` suffix is
/// URL convention, not part of the name.
pub(super) fn repo_name(segment: &str) -> &str {
    segment.strip_suffix(".git").unwrap_or(segment)
}

pub(super) fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

pub(super) fn text_response(status: StatusCode, message: &str) -> Response {
    (status, message.to_owned()).into_response()
}
