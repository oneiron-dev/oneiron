//! `POST /v1/hooks/linear`: the signed Linear webhook door (OF-427 C1–C4,
//! C11). Keyless, like the built-in channels' provider webhooks: the
//! `Linear-Signature` HMAC-SHA256 over the raw body, keyed by the custody
//! secret the owner stored for the Linear connector and read only through
//! the credential door, authenticates each delivery before any parse,
//! archive or write. The `Linear-Delivery` header is the delivery's identity;
//! its permanent dedupe answers a replay, so no timestamp window applies.
//!
//! A verified delivery is normalized under the host's tracker mapping, its
//! body archived in the vault, and applied by the engine's ordinary inbound
//! merge. The reply is the engine's receipt; a replay answers the stored one.

use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use hmac::{Hmac, Mac};
use oneiron::linear_sync::LinearWebhookReceipt;
use oneiron::{LinearSyncError, Vault};
use oneiron_linear::normalize_issue_webhook;
use sha2::Sha256;

use crate::server::SyncServer;

/// The Linear webhook URL.
pub(crate) const LINEAR_WEBHOOK_PATH: &str = "/v1/hooks/linear";
/// The header carrying the hex HMAC-SHA256 of the raw body.
pub(crate) const LINEAR_SIGNATURE_HEADER: &str = "linear-signature";
/// The header naming the delivery.
pub(crate) const LINEAR_DELIVERY_HEADER: &str = "linear-delivery";
/// The custody name of the webhook's signing secret.
pub(crate) const LINEAR_WEBHOOK_SECRET: &str = "linear.webhook_signing_secret";
/// The effector the signing secret is bound to.
pub(crate) const LINEAR_SECRET_EFFECTOR: &str = "connector:linear";
/// The channel a delivery's archived body is kept under.
const LINEAR_CHANNEL: &str = "linear";

pub(crate) fn routes() -> Router<Arc<SyncServer>> {
    Router::new().route(LINEAR_WEBHOOK_PATH, post(linear_webhook))
}

/// What the webhook answers. Linear resends a delivery a non-2xx answers,
/// so only a delivery it should send again is refused with a retryable code.
enum Reply {
    Receipt(Box<LinearWebhookReceipt>),
    Refused(StatusCode, &'static str),
}

impl IntoResponse for Reply {
    fn into_response(self) -> Response {
        match self {
            Self::Receipt(receipt) => (StatusCode::OK, axum::Json(*receipt)).into_response(),
            Self::Refused(status, code) => {
                (status, axum::Json(serde_json::json!({ "error": code }))).into_response()
            }
        }
    }
}

const UNSIGNED: Reply = Reply::Refused(StatusCode::UNAUTHORIZED, "linear_webhook_unsigned");
const NOT_CONFIGURED: Reply =
    Reply::Refused(StatusCode::NOT_FOUND, "linear_webhook_not_configured");
const FAILED: Reply = Reply::Refused(StatusCode::INTERNAL_SERVER_ERROR, "linear_webhook_failed");

async fn linear_webhook(
    State(server): State<Arc<SyncServer>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let signature = header(&headers, LINEAR_SIGNATURE_HEADER);
    let delivery = header(&headers, LINEAR_DELIVERY_HEADER);
    let vault = Arc::clone(server.vault());
    match tokio::task::spawn_blocking(move || deliver(&vault, signature, delivery, &body)).await {
        Ok(reply) => reply.into_response(),
        Err(_) => FAILED.into_response(),
    }
}

/// One delivery, verified before anything reads its body.
fn deliver(
    vault: &Vault,
    signature: Option<String>,
    delivery: Option<String>,
    body: &[u8],
) -> Reply {
    let tracker = match super::webhook_tracker() {
        Ok(Some(tracker)) => tracker,
        Ok(None) => return NOT_CONFIGURED,
        Err(error) => {
            tracing::warn!(%error, "the Linear webhook mapping is unreadable");
            return NOT_CONFIGURED;
        }
    };
    let Some(expected) = signature.as_deref().and_then(decode_hex) else {
        return UNSIGNED;
    };
    match signature_matches(vault, body, &expected) {
        Ok(true) => {}
        Ok(false) => return UNSIGNED,
        Err(error) => {
            tracing::warn!(%error, "the Linear webhook signing secret is unavailable");
            return UNSIGNED;
        }
    }
    let Some(delivery) = delivery.filter(|id| !id.trim().is_empty()) else {
        return Reply::Refused(StatusCode::BAD_REQUEST, "linear_webhook_delivery_missing");
    };
    let Ok(event) = normalize_issue_webhook(body, &delivery, &tracker) else {
        return Reply::Refused(StatusCode::BAD_REQUEST, "linear_webhook_malformed");
    };
    // A replay answers before the body is archived again.
    match vault.linear_webhook_replay(&event.delivery_id, &event.body_digest) {
        Ok(Some(receipt)) => return Reply::Receipt(Box::new(receipt)),
        Ok(None) => {}
        Err(error) => return refused(&error),
    }
    let now = unix_now();
    let payload_ref = match vault.archive_provider_event(LINEAR_CHANNEL, &delivery, body, now) {
        Ok(payload_ref) => payload_ref,
        Err(error) => {
            tracing::warn!(%error, "a Linear webhook body was not archived");
            return FAILED;
        }
    };
    match vault.apply_linear_webhook(&event, Some(&payload_ref), now) {
        Ok(receipt) => Reply::Receipt(Box::new(receipt)),
        Err(error) => refused(&error),
    }
}

fn refused(error: &LinearSyncError) -> Reply {
    match error {
        LinearSyncError::DeliveryReused => {
            Reply::Refused(StatusCode::CONFLICT, "linear_webhook_delivery_reused")
        }
        // The TASK or its link moved under the apply: Linear sends it again.
        LinearSyncError::Conflict { .. } | LinearSyncError::LinkConflict { .. } => {
            Reply::Refused(StatusCode::SERVICE_UNAVAILABLE, "linear_webhook_retry")
        }
        other => {
            tracing::warn!(error = %other, "a Linear webhook delivery failed");
            FAILED
        }
    }
}

/// Whether `expected` is the HMAC-SHA256 of `body` under the stored signing
/// secret, read only through the credential door.
fn signature_matches(vault: &Vault, body: &[u8], expected: &[u8]) -> oneiron::Result<bool> {
    let mut matched = false;
    vault.inject_secret_at_door(
        LINEAR_WEBHOOK_SECRET,
        LINEAR_SECRET_EFFECTOR,
        &mut |value: &[u8]| {
            let mut mac = Hmac::<Sha256>::new_from_slice(value.trim_ascii()).map_err(|_| {
                oneiron::Error::InvalidConfig("the stored signing secret is unusable".to_owned())
            })?;
            mac.update(body);
            matched = mac.verify_slice(expected).is_ok();
            Ok(())
        },
    )?;
    Ok(matched)
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    if text.len() % 2 != 0 || !text.is_ascii() {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).ok())
        .collect()
}

fn header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}
