//! `POST /v1/hooks/stripe/booking-deposit`: Stripe's signed word about a
//! deposit's PaymentIntent. Keyless, like the other provider webhooks: the
//! `Stripe-Signature` HMAC-SHA256 over `"{t}.{raw body}"`, keyed by the
//! owner's endpoint signing secret read only through the custody door,
//! authenticates each delivery before any parse or write, inside a five
//! minute window around its timestamp. Each Stripe event id applies once
//! (`record_deposit_provider_event`), so a resend changes nothing.
//!
//! Three event types move a deposit: `payment_intent.amount_capturable_updated`
//! (the card is authorized), `payment_intent.payment_failed` (refused; the
//! hold stays live for a retry) and `payment_intent.canceled`. Every other
//! verified event is acknowledged and ignored. A live-mode event is refused:
//! deposits run in test mode only.

use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use oneiron::Vault;
use oneiron::booking::BookingError;
use oneiron::booking::lifecycle::{
    DepositProviderEvent, DepositProviderEventKind, DepositProviderEventOutcome,
    record_deposit_provider_event,
};
use serde::Deserialize;

use super::{DEPOSIT_EFFECTOR, STRIPE_WEBHOOK_SECRET_NAME};
use crate::server::SyncServer;

/// The deposit webhook URL the owner registers in his Stripe dashboard.
pub(crate) const STRIPE_DEPOSIT_WEBHOOK_PATH: &str = "/v1/hooks/stripe/booking-deposit";

/// The header carrying `t=<unix seconds>,v1=<hex HMAC>[,v1=...]`.
const STRIPE_SIGNATURE_HEADER: &str = "stripe-signature";

/// How far a delivery's signed timestamp may sit from this server's clock:
/// Stripe's own default tolerance.
const SIGNATURE_TOLERANCE_SECS: u64 = 5 * 60;

/// The largest event body read.
const MAX_WEBHOOK_BODY_BYTES: usize = 256 * 1024;

/// The longest refusal reason kept from an event.
const MAX_REASON_BYTES: usize = 120;

pub(crate) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route(STRIPE_DEPOSIT_WEBHOOK_PATH, post(stripe_deposit_webhook))
        .layer(DefaultBodyLimit::max(MAX_WEBHOOK_BODY_BYTES))
}

/// What the webhook answers. Stripe resends an event a non-2xx answers, so
/// only an event it should send again gets a retryable code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WebhookReply {
    /// Applied, already applied, ignored, or about no deposit.
    Accepted,
    Refused(StatusCode, &'static str),
}

impl IntoResponse for WebhookReply {
    fn into_response(self) -> Response {
        match self {
            Self::Accepted => (
                StatusCode::OK,
                axum::Json(serde_json::json!({ "received": true })),
            )
                .into_response(),
            Self::Refused(status, code) => {
                (status, axum::Json(serde_json::json!({ "error": code }))).into_response()
            }
        }
    }
}

const UNSIGNED: WebhookReply =
    WebhookReply::Refused(StatusCode::UNAUTHORIZED, "stripe_deposit_webhook_unsigned");
const FAILED: WebhookReply = WebhookReply::Refused(
    StatusCode::INTERNAL_SERVER_ERROR,
    "stripe_deposit_webhook_failed",
);

async fn stripe_deposit_webhook(
    State(server): State<Arc<SyncServer>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let signature = headers
        .get(STRIPE_SIGNATURE_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let vault = Arc::clone(server.vault());
    match tokio::task::spawn_blocking(move || {
        deliver(&vault, signature.as_deref(), &body, unix_now())
    })
    .await
    {
        Ok(reply) => reply.into_response(),
        Err(_) => FAILED.into_response(),
    }
}

/// The parts of a `Stripe-Signature` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StripeSignature {
    pub timestamp: u64,
    /// Every `v1` signature: more than one while the owner rolls the secret.
    pub v1: Vec<Vec<u8>>,
}

/// Parses `t=<secs>,v1=<hex>[,...]`; other schemes (`v0`) are ignored.
pub(crate) fn parse_signature_header(header: &str) -> Option<StripeSignature> {
    let mut timestamp = None;
    let mut v1 = Vec::new();
    for part in header.split(',') {
        let (key, value) = part.trim().split_once('=')?;
        match key {
            "t" => timestamp = Some(value.parse::<u64>().ok()?),
            "v1" => v1.push(decode_hex(value)?),
            _ => {}
        }
    }
    let timestamp = timestamp?;
    (!v1.is_empty()).then_some(StripeSignature { timestamp, v1 })
}

/// Whether `header` signs `body` under the stored endpoint secret, inside
/// the tolerance window around `now`.
fn signed(vault: &Vault, header: Option<&str>, body: &[u8], now: u64) -> Result<bool, String> {
    let Some(signature) = header.and_then(parse_signature_header) else {
        return Ok(false);
    };
    if signature.timestamp.abs_diff(now) > SIGNATURE_TOLERANCE_SECS {
        return Ok(false);
    }
    let stamp = signature.timestamp.to_string();
    for expected in &signature.v1 {
        let matched = crate::builtin_host::hmac_matches(
            vault,
            STRIPE_WEBHOOK_SECRET_NAME,
            DEPOSIT_EFFECTOR,
            &[stamp.as_bytes(), b".", body],
            expected,
        )
        .map_err(|error| error.to_string())?;
        if matched {
            return Ok(true);
        }
    }
    Ok(false)
}

#[derive(Deserialize)]
struct StripeEvent {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    livemode: bool,
    data: StripeEventData,
}

#[derive(Deserialize)]
struct StripeEventData {
    object: StripePaymentIntentObject,
}

#[derive(Deserialize)]
struct StripePaymentIntentObject {
    id: String,
    #[serde(default)]
    amount_capturable: u64,
    #[serde(default)]
    currency: String,
    #[serde(default)]
    last_payment_error: Option<StripePaymentError>,
}

#[derive(Deserialize)]
struct StripePaymentError {
    #[serde(default)]
    decline_code: Option<String>,
    #[serde(default)]
    code: Option<String>,
}

/// The deposit event a verified Stripe event carries, if it carries one.
fn provider_event(event: StripeEvent) -> Option<DepositProviderEvent> {
    let object = event.data.object;
    let kind = match event.kind.as_str() {
        "payment_intent.amount_capturable_updated" => DepositProviderEventKind::Authorized {
            amount_minor: object.amount_capturable,
            currency: object.currency,
        },
        "payment_intent.payment_failed" => {
            let reason = object
                .last_payment_error
                .and_then(|error| error.decline_code.or(error.code))
                .unwrap_or_else(|| "payment_failed".to_owned());
            DepositProviderEventKind::AuthorizationFailed {
                reason: reason.chars().take(MAX_REASON_BYTES).collect(),
            }
        }
        "payment_intent.canceled" => DepositProviderEventKind::Canceled,
        _ => return None,
    };
    Some(DepositProviderEvent {
        event_id: event.id,
        payment_id: object.id,
        kind,
    })
}

/// One delivery, verified before anything reads its body.
pub(crate) fn deliver(
    vault: &Vault,
    signature: Option<&str>,
    body: &[u8],
    now: u64,
) -> WebhookReply {
    match signed(vault, signature, body, now) {
        Ok(true) => {}
        Ok(false) => return UNSIGNED,
        Err(error) => {
            tracing::warn!(%error, "the Stripe deposit webhook signing secret is unavailable");
            return UNSIGNED;
        }
    }
    let Ok(event) = serde_json::from_slice::<StripeEvent>(body) else {
        // A verified event of another object (a charge, a refund) is still
        // Stripe's: acknowledged, so it is not resent.
        return if serde_json::from_slice::<serde_json::Value>(body).is_ok() {
            WebhookReply::Accepted
        } else {
            WebhookReply::Refused(StatusCode::BAD_REQUEST, "stripe_deposit_webhook_malformed")
        };
    };
    if event.livemode {
        tracing::warn!(
            "a live-mode Stripe event was refused: booking deposits run in test mode only"
        );
        return WebhookReply::Refused(StatusCode::BAD_REQUEST, "stripe_deposit_live_mode_refused");
    }
    let Some(event) = provider_event(event) else {
        return WebhookReply::Accepted;
    };
    match record_deposit_provider_event(vault, &event, now) {
        Ok(DepositProviderEventOutcome::TermsMismatch) => {
            tracing::warn!(
                payment = %event.payment_id,
                "a Stripe authorization for other than the deposit's terms was not applied"
            );
            WebhookReply::Accepted
        }
        Ok(_) => WebhookReply::Accepted,
        Err(BookingError::InvalidConstraint(_)) => {
            WebhookReply::Refused(StatusCode::BAD_REQUEST, "stripe_deposit_webhook_malformed")
        }
        Err(error) => {
            tracing::warn!(%error, "a Stripe deposit event was not recorded");
            FAILED
        }
    }
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

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}
