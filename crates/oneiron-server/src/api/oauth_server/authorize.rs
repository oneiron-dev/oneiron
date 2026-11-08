//! `GET /oauth/authorize` and its poll, `GET /oauth/authorize/status`.
//!
//! A request whose client or redirect URI this vault cannot vouch for gets an error page and is
//! never redirected (RFC 6749 §4.1.2.1). Every later error goes back to the client's redirect
//! URI with `error`, its `state` and `iss` (RFC 9207). A valid request is recorded, the vault
//! owner gets one inbox ask, and the browser gets a page that shows the client, the tier asked
//! and a match code the ask shows too. The page polls with its token in a header; once the owner
//! answers, the poll hands it the redirect: the code on an allow, `access_denied` on a deny.
//!
//! The page is open to anyone, so its flood cap is asked before its client is read or fetched
//! ([`super::OAuthFloodCaps`]); the poll is not capped.

use std::sync::Arc;

use axum::Extension;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use base64::Engine as _;
use oneiron::authority::{
    OAUTH_STATE_MAX_BYTES, OAuthAuthorizationPending, OAuthAuthorizationStart,
    OAuthAuthorizationStatus, OAuthClientRecord, oauth_code_challenge_admitted,
    oauth_requested_tier,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::client_document::resolve_client;
use super::html::escape_html;
use super::{OAuthFloodCaps, OAuthIdentity, not_found, now};
use crate::auth::ClientAddress;
use crate::server::SyncServer;

/// The header the page sends its token in; `authorize.js` names the same one.
const PAGE_TOKEN_HEADER: &str = "x-oneiron-oauth-page";
/// The page's one script, allowed by its digest alone.
const PAGE_SCRIPT: &str = include_str!("authorize.js");

const UNREADABLE: &str =
    "This sign-in request could not be read. Start the sign-in again from the app.";
const UNKNOWN_CLIENT: &str =
    "This app is not known to this vault. Start the sign-in again from the app.";
const UNKNOWN_REDIRECT: &str =
    "This sign-in request names a return address the app did not register.";

/// The authorize request's parameters; every other is ignored.
#[derive(Deserialize)]
pub(super) struct AuthorizeQuery {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    state: Option<String>,
    resource: Option<String>,
    scope: Option<String>,
}

/// Where a request's errors go once its client and redirect URI are known.
struct ClientRedirect<'a> {
    redirect_uri: &'a str,
    state: Option<&'a str>,
    issuer: &'a str,
}

impl ClientRedirect<'_> {
    /// The browser sent back to the client with `error` (RFC 6749 §4.1.2.1).
    fn error(&self, code: &str) -> Response {
        match client_redirect_url(
            self.redirect_uri,
            &[("error", code)],
            self.state,
            self.issuer,
        ) {
            Some(url) => (StatusCode::FOUND, [(header::LOCATION, url)]).into_response(),
            None => error_page(UNKNOWN_REDIRECT),
        }
    }
}

/// `redirect_uri` with `params`, the client's `state` and the issuer as `iss` appended to its
/// query.
fn client_redirect_url(
    redirect_uri: &str,
    params: &[(&str, &str)],
    state: Option<&str>,
    issuer: &str,
) -> Option<String> {
    let mut url = reqwest::Url::parse(redirect_uri).ok()?;
    {
        let mut query = url.query_pairs_mut();
        for (name, value) in params {
            query.append_pair(name, value);
        }
        if let Some(state) = state {
            query.append_pair("state", state);
        }
        query.append_pair("iss", issuer);
    }
    Some(url.to_string())
}

/// `GET /oauth/authorize`: validates the request, records it with the owner's ask, and shows
/// the page that waits for his answer; past the flood cap, the cap's 429 before anything else.
pub(super) async fn page(
    State(server): State<Arc<SyncServer>>,
    Extension(caps): Extension<Arc<OAuthFloodCaps>>,
    ClientAddress(source): ClientAddress,
    query: Result<Query<AuthorizeQuery>, QueryRejection>,
) -> Response {
    let Some(identity) = OAuthIdentity::of(&server) else {
        return not_found();
    };
    if let Some(shed) = caps.shed_authorization(source) {
        return shed;
    }
    let Ok(Query(query)) = query else {
        return error_page(UNREADABLE);
    };
    let Some(client_id) = query.client_id.as_deref().filter(|id| !id.is_empty()) else {
        return error_page(UNREADABLE);
    };
    let now = now();
    let Some(client) = resolve_client(&server, client_id, now).await else {
        return error_page(UNKNOWN_CLIENT);
    };
    let Some(redirect_uri) = query
        .redirect_uri
        .as_deref()
        .filter(|uri| client.admits_redirect_uri(uri))
    else {
        return error_page(UNKNOWN_REDIRECT);
    };
    if query
        .state
        .as_deref()
        .is_some_and(|state| state.len() > OAUTH_STATE_MAX_BYTES)
    {
        return error_page(UNREADABLE);
    }
    let redirect = ClientRedirect {
        redirect_uri,
        state: query.state.as_deref(),
        issuer: identity.issuer(),
    };
    if query.response_type.as_deref() != Some("code") {
        return redirect.error("unsupported_response_type");
    }
    let Some(code_challenge) = query.code_challenge.as_deref().filter(|challenge| {
        query.code_challenge_method.as_deref() == Some("S256")
            && oauth_code_challenge_admitted(challenge)
    }) else {
        return redirect.error("invalid_request");
    };
    let resource = identity.resource();
    if query.resource.as_deref() != Some(resource.as_str()) {
        return redirect.error("invalid_target");
    }
    let Some(tier) = oauth_requested_tier(query.scope.as_deref()) else {
        return redirect.error("invalid_scope");
    };
    let Some(issuer) = server.host_issuer() else {
        return redirect.error("temporarily_unavailable");
    };
    let start = OAuthAuthorizationStart {
        client: &client,
        redirect_uri,
        code_challenge,
        state: query.state.as_deref(),
        resource: &resource,
        tier,
    };
    match server
        .vault()
        .begin_oauth_authorization(issuer, &start, now)
    {
        Ok(Some(pending)) => consent_page(&client, redirect_uri, &pending),
        Ok(None) => redirect.error("temporarily_unavailable"),
        Err(error) => {
            tracing::warn!(%error, "recording an OAuth authorization request failed");
            redirect.error("server_error")
        }
    }
}

/// `GET /oauth/authorize/status`: where the request the page's token proves stands. An answer
/// that settled it carries the redirect the page sends the browser to.
pub(super) async fn status(State(server): State<Arc<SyncServer>>, headers: HeaderMap) -> Response {
    let Some(identity) = OAuthIdentity::of(&server) else {
        return not_found();
    };
    let Some(page_token) = headers
        .get(PAGE_TOKEN_HEADER)
        .and_then(|value| value.to_str().ok())
    else {
        return status_reply(StatusCode::BAD_REQUEST, "unknown", None);
    };
    let Some(issuer) = server.host_issuer() else {
        return status_reply(StatusCode::SERVICE_UNAVAILABLE, "unavailable", None);
    };
    match server
        .vault()
        .collect_oauth_authorization(issuer, page_token, now())
    {
        Ok(OAuthAuthorizationStatus::Pending) => status_reply(StatusCode::OK, "pending", None),
        Ok(OAuthAuthorizationStatus::Allowed {
            redirect_uri,
            state,
            code,
        }) => match client_redirect_url(
            &redirect_uri,
            &[("code", code.as_str())],
            state.as_deref(),
            identity.issuer(),
        ) {
            Some(url) => status_reply(StatusCode::OK, "allowed", Some(url)),
            None => status_reply(StatusCode::INTERNAL_SERVER_ERROR, "error", None),
        },
        Ok(OAuthAuthorizationStatus::Denied {
            redirect_uri,
            state,
        }) => match client_redirect_url(
            &redirect_uri,
            &[("error", "access_denied")],
            state.as_deref(),
            identity.issuer(),
        ) {
            Some(url) => status_reply(StatusCode::OK, "denied", Some(url)),
            None => status_reply(StatusCode::INTERNAL_SERVER_ERROR, "error", None),
        },
        Ok(OAuthAuthorizationStatus::Expired) => status_reply(StatusCode::OK, "expired", None),
        Ok(OAuthAuthorizationStatus::Unknown) => {
            status_reply(StatusCode::NOT_FOUND, "unknown", None)
        }
        Err(error) => {
            tracing::warn!(%error, "reading an OAuth authorization request failed");
            status_reply(StatusCode::INTERNAL_SERVER_ERROR, "error", None)
        }
    }
}

/// The poll's JSON reply: `{"status": ..., "redirect"?: ...}`.
fn status_reply(status: StatusCode, word: &str, redirect: Option<String>) -> Response {
    let mut body = serde_json::json!({ "status": word });
    if let (Some(redirect), Some(fields)) = (redirect, body.as_object_mut()) {
        fields.insert("redirect".to_owned(), redirect.into());
    }
    (status, axum::Json(body)).into_response()
}

/// The page that waits for the owner's answer: the client, its host, the tier asked and the
/// match code, every one escaped, and the script that polls.
fn consent_page(
    client: &OAuthClientRecord,
    redirect_uri: &str,
    pending: &OAuthAuthorizationPending,
) -> Response {
    let digest =
        base64::engine::general_purpose::STANDARD.encode(Sha256::digest(PAGE_SCRIPT.as_bytes()));
    let csp = format!(
        "default-src 'none'; script-src 'sha256-{digest}'; connect-src 'self'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    );
    let html = format!(
        "<!doctype html><html lang=en><meta charset=utf-8><meta name=referrer content=no-referrer><meta name=viewport content=\"width=device-width,initial-scale=1\"><meta name=oauth-page-token content=\"{token}\"><title>Sign-in request</title><main><h1>Sign-in request</h1><p><strong>{name}</strong> ({host}) asks to use this vault with <strong>{tier}</strong> access.</p><p>Match code: <code>{code}</code></p><p>Open your inbox and check that the request there shows the same match code, then allow or deny it.</p><p id=status role=status>Waiting for your answer.</p></main><script>{PAGE_SCRIPT}</script></html>",
        token = escape_html(&pending.page_token),
        name = escape_html(client.display_name()),
        host = escape_html(&client.display_host(redirect_uri)),
        tier = escape_html(pending.tier.wire_name()),
        code = escape_html(&pending.match_code),
    );
    ([(header::CONTENT_SECURITY_POLICY, csp)], Html(html)).into_response()
}

/// The page a request gets when the vault cannot send the browser back to its client: what went
/// wrong, escaped, and no script.
fn error_page(message: &str) -> Response {
    let html = format!(
        "<!doctype html><html lang=en><meta charset=utf-8><meta name=referrer content=no-referrer><meta name=viewport content=\"width=device-width,initial-scale=1\"><title>Sign-in request</title><main><h1>Sign-in request</h1><p>{}</p></main></html>",
        escape_html(message)
    );
    (
        StatusCode::BAD_REQUEST,
        [(
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        )],
        Html(html),
    )
        .into_response()
}
