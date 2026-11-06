//! `POST /oauth/token` (RFC 6749 §3.2, form-encoded): an authorization code with its PKCE
//! verifier, or a refresh token, traded for an access token and the next refresh token. And
//! `POST /oauth/revoke` (RFC 7009): the presented token's whole family revoked. Every client is
//! public: it names itself with `client_id` and holds no secret.

use std::sync::Arc;

use axum::Form;
use axum::extract::State;
use axum::extract::rejection::FormRejection;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use oneiron::authority::{OAuthCodeExchange, OAuthRefresh, OAuthTokenRefusal, OAuthTokens};
use serde::Deserialize;

use super::{OAuthIdentity, not_found, now, oauth_error};
use crate::server::SyncServer;

/// The token request's parameters; every other is ignored.
#[derive(Deserialize)]
pub(super) struct TokenForm {
    grant_type: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
    resource: Option<String>,
    scope: Option<String>,
}

/// The revocation request's parameters; `token_type_hint` is read by no one, since the token
/// says its own kind.
#[derive(Deserialize)]
pub(super) struct RevokeForm {
    token: Option<String>,
    client_id: Option<String>,
}

/// `POST /oauth/token`: RFC 6749 §5.1's response, or §5.2's error.
pub(super) async fn token(
    State(server): State<Arc<SyncServer>>,
    form: Result<Form<TokenForm>, FormRejection>,
) -> Response {
    if OAuthIdentity::of(&server).is_none() {
        return not_found();
    }
    let Ok(Form(form)) = form else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let Some(issuer) = server.host_issuer() else {
        return oauth_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    };
    let issued = match form.grant_type.as_deref() {
        Some("authorization_code") => {
            let (Some(code), Some(client_id), Some(redirect_uri), Some(code_verifier)) = (
                form.code.as_deref(),
                form.client_id.as_deref(),
                form.redirect_uri.as_deref(),
                form.code_verifier.as_deref(),
            ) else {
                return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
            };
            server.vault().exchange_oauth_code(
                issuer,
                &OAuthCodeExchange {
                    code,
                    client_id,
                    redirect_uri,
                    code_verifier,
                    resource: form.resource.as_deref(),
                },
                now(),
            )
        }
        Some("refresh_token") => {
            let (Some(refresh_token), Some(client_id)) =
                (form.refresh_token.as_deref(), form.client_id.as_deref())
            else {
                return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
            };
            server.vault().refresh_oauth_token(
                issuer,
                &OAuthRefresh {
                    refresh_token,
                    client_id,
                    resource: form.resource.as_deref(),
                    scope: form.scope.as_deref(),
                },
                now(),
            )
        }
        Some(_) => return oauth_error(StatusCode::BAD_REQUEST, "unsupported_grant_type"),
        None => return oauth_error(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    match issued {
        Ok(Ok(tokens)) => token_response(tokens),
        Ok(Err(refusal)) => token_refusal(refusal),
        Err(error) => {
            tracing::warn!(%error, "an OAuth token request failed");
            oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error")
        }
    }
}

/// RFC 6749 §5.1's body; the private layer marks it `no-store`.
fn token_response(tokens: OAuthTokens) -> Response {
    axum::Json(serde_json::json!({
        "access_token": tokens.access_token,
        "token_type": "Bearer",
        "expires_in": tokens.expires_in,
        "refresh_token": tokens.refresh_token,
        "scope": tokens.scope,
    }))
    .into_response()
}

/// RFC 6749 §5.2's error, at 400.
fn token_refusal(refusal: OAuthTokenRefusal) -> Response {
    oauth_error(StatusCode::BAD_REQUEST, refusal.error_code())
}

/// `POST /oauth/revoke`: always 200 (RFC 7009 §2.2), whether the token was known, lapsed,
/// another client's, or none at all, so the answer says nothing of it.
pub(super) async fn revoke(
    State(server): State<Arc<SyncServer>>,
    form: Result<Form<RevokeForm>, FormRejection>,
) -> Response {
    if OAuthIdentity::of(&server).is_none() {
        return not_found();
    }
    if let (Ok(Form(form)), Some(issuer)) = (form, server.host_issuer())
        && let Some(token) = form.token.as_deref()
        && let Err(error) =
            server
                .vault()
                .revoke_oauth_token(issuer, token, form.client_id.as_deref(), now())
    {
        tracing::warn!(%error, "an OAuth token revocation failed");
    }
    StatusCode::OK.into_response()
}
