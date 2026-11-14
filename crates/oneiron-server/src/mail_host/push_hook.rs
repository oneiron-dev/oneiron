//! `POST /v1/hooks/gmail/push`: Gmail's change notices, delivered by the
//! owner's Pub/Sub push subscription (census L2-17; ruling PUSH-TRANSPORT =
//! A). Keyless, like the other provider hooks: the OIDC token Google puts
//! on each delivery is the authentication. It must be signed by Google
//! (RS256, a key of `[gmail_push] jwks_uri`), issued by Google, for the
//! section's `audience`, and name its `service_account` as a verified email;
//! anything else answers 401 and wakes nothing.
//!
//! A notice names a mailbox and its new history id, never mail. The engine
//! answers the Active mailboxes it wakes (`Vault::mail_push_notice`), and
//! the mail worker steps each at once. A signed delivery is acknowledged
//! with 204 whatever it names, so Pub/Sub does not deliver it again: the
//! worker's 300 s pass reads every source from its committed anchor, so a
//! notice this hook could not read is read there. Served only while the
//! host sets `[gmail_push]`.

use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode, header::AUTHORIZATION};
use axum::routing::post;
use base64::Engine as _;
use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use oneiron::mail_pack::MailProvider;
use serde::Deserialize;
use serde_json::Value;

use crate::config::GmailPushConfig;
use crate::server::SyncServer;

/// The push subscription's endpoint, on this host's API origin.
pub(crate) const GMAIL_PUSH_PATH: &str = "/v1/hooks/gmail/push";
/// One Pub/Sub delivery of one Gmail notice, with room to spare.
const MAX_PUSH_BODY_BYTES: usize = 64 * 1024;
/// The issuers Google's OIDC tokens name.
const GOOGLE_ISSUERS: [&str; 2] = ["accounts.google.com", "https://accounts.google.com"];

/// The hook's route, or none while the host sets no `[gmail_push]`.
pub(crate) fn routes(server: &SyncServer) -> Router<Arc<SyncServer>> {
    if server.config.gmail_push.is_none() {
        return Router::new();
    }
    Router::new()
        .route(GMAIL_PUSH_PATH, post(gmail_push))
        .layer(DefaultBodyLimit::max(MAX_PUSH_BODY_BYTES))
}

/// `POST /v1/hooks/gmail/push`: one Pub/Sub push delivery.
async fn gmail_push(
    State(server): State<Arc<SyncServer>>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    let Some(config) = server.config.gmail_push.clone() else {
        return StatusCode::NOT_FOUND;
    };
    let Some(token) = bearer(&headers) else {
        return StatusCode::UNAUTHORIZED;
    };
    // The key set is read over blocking HTTP, and the notice in a read of
    // the vault: both off the async runtime.
    let answer = tokio::task::spawn_blocking(move || {
        if !signed_by_the_subscription(&token, &config) {
            return StatusCode::UNAUTHORIZED;
        }
        if let Some((address, anchor)) = notice(&body) {
            match server
                .vault()
                .mail_push_notice(MailProvider::Google, &address, &anchor)
            {
                Ok(woken) => server.mail_source_wakes.wake(woken),
                Err(error) => tracing::warn!(error = %error, "gmail push notice unread"),
            }
        }
        StatusCode::NO_CONTENT
    })
    .await;
    answer.unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
}

/// The request's bearer token.
fn bearer(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?.trim();
    let (scheme, token) = value.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && !token.trim().is_empty())
        .then(|| token.trim().to_owned())
}

/// The claims of Google's token this hook reads beyond the checked ones.
#[derive(Deserialize)]
struct PushIdentity {
    email: Option<String>,
    email_verified: Option<bool>,
}

/// Whether `token` is Google's OIDC token for the push subscription the
/// section names.
fn signed_by_the_subscription(token: &str, config: &GmailPushConfig) -> bool {
    let Ok(header) = decode_header(token) else {
        return false;
    };
    if header.alg != Algorithm::RS256 {
        return false;
    }
    let Some(kid) = header.kid.as_deref() else {
        return false;
    };
    // A rotated key may not be in the cached set: read it again once.
    let Some(jwk) = google_key(&config.jwks_uri, kid, false)
        .or_else(|| google_key(&config.jwks_uri, kid, true))
    else {
        return false;
    };
    let Ok(key) = DecodingKey::from_jwk(&jwk) else {
        return false;
    };
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&GOOGLE_ISSUERS);
    validation.set_audience(&[config.audience.as_str()]);
    validation.set_required_spec_claims(&["iss", "aud", "exp"]);
    let Ok(data) = decode::<PushIdentity>(token, &key, &validation) else {
        return false;
    };
    data.claims.email_verified == Some(true)
        && data
            .claims
            .email
            .is_some_and(|email| email.eq_ignore_ascii_case(&config.service_account))
}

/// The key `kid` of the set at `uri`, read again from its source when
/// `refresh`.
fn google_key(uri: &str, kid: &str, refresh: bool) -> Option<Jwk> {
    let body = crate::oauth_relay::identity_provider_jwks(uri, refresh).ok()?;
    let keys: JwkSet = serde_json::from_str(&body).ok()?;
    keys.find(kid).cloned()
}

/// A Pub/Sub push delivery.
#[derive(Deserialize)]
struct PushDelivery {
    message: PushMessage,
}

#[derive(Deserialize)]
struct PushMessage {
    /// The published message, base64.
    data: String,
}

/// Gmail's notice: the mailbox and its new history id.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GmailNotice {
    email_address: String,
    /// A number or a string of one.
    history_id: Value,
}

/// The mailbox and history id a delivery names, if it reads as Gmail's
/// notice.
fn notice(body: &[u8]) -> Option<(String, String)> {
    let delivery: PushDelivery = serde_json::from_slice(body).ok()?;
    let data = base64::engine::general_purpose::STANDARD
        .decode(delivery.message.data.trim())
        .ok()?;
    let notice: GmailNotice = serde_json::from_slice(&data).ok()?;
    let anchor = match notice.history_id {
        Value::String(id) => id,
        Value::Number(id) => id.to_string(),
        _ => return None,
    };
    Some((notice.email_address, anchor))
}
