//! The provider webhooks of the served built-in channels (OF-519). Keyless,
//! like the cooperative deletion routes: the provider's HMAC over the raw
//! body is the authentication, keyed by the signing secret the owner stored
//! for the checked connection and read only through the credential door.
//! A verified event is rechecked against the pack and its check, archived
//! in the vault, parsed by the channel's adapter and queued on the unscoped
//! surface-event door, whose routing boundary gates the built-in pack again.

use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine;
use hmac::{Hmac, Mac};
use oneiron::Vault;
use oneiron::channel_identity_provider::{
    ChannelIdentityProviderAdapter, ChannelIdentityProviderInbound, LINE_CHANNEL,
    LineOfficialAccountInbound, SLACK_CHANNEL, SlackProviderInbound, SlackSharedPresenceAdapter,
};
use oneiron::skill_hub::pack_catalog::PackSetupSecret;
use oneiron::surface_event::{InboundSurfaceEventInput, SurfaceEventAdmission};
use serde_json::Value;
use sha2::Sha256;

use super::handles::{LINE_CONNECTION, LineHandle, SLACK_CONNECTION, SlackHandle};
use crate::server::SyncServer;

/// The Slack Events API request URL.
pub(crate) const SLACK_EVENTS_PATH: &str = "/v1/hooks/slack/events";
/// The Slack app's OAuth redirect URL.
pub(crate) const SLACK_OAUTH_PATH: &str = "/v1/hooks/slack/oauth";
/// The LINE Messaging API webhook URL.
pub(crate) const LINE_WEBHOOK_PATH: &str = "/v1/hooks/line/webhook";
/// One Slack event callback, with room to spare.
const MAX_SLACK_BODY_BYTES: usize = 256 * 1024;
/// One LINE delivery may batch many events.
const MAX_LINE_BODY_BYTES: usize = 1024 * 1024;
/// Slack's replay window for a signed request.
const SLACK_MAX_SKEW_SECS: u64 = 5 * 60;

pub(crate) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route(SLACK_EVENTS_PATH, post(slack_events))
        .layer(DefaultBodyLimit::max(MAX_SLACK_BODY_BYTES))
        .route(SLACK_OAUTH_PATH, get(super::slack_app::slack_oauth))
        .merge(
            Router::new()
                .route(LINE_WEBHOOK_PATH, post(line_webhook))
                .layer(DefaultBodyLimit::max(MAX_LINE_BODY_BYTES)),
        )
}

/// What a webhook answers. A provider gets a 2xx for anything it should
/// not resend: an event this host does not route is acknowledged and logged.
enum Reply {
    Ack,
    Challenge(String),
    Refused(StatusCode, &'static str),
}

impl IntoResponse for Reply {
    fn into_response(self) -> Response {
        match self {
            Self::Ack => StatusCode::OK.into_response(),
            Self::Challenge(challenge) => {
                axum::Json(serde_json::json!({ "challenge": challenge })).into_response()
            }
            Self::Refused(status, reason) => (status, reason).into_response(),
        }
    }
}

/// `POST /v1/hooks/slack/events`: one signed Events API delivery.
async fn slack_events(
    State(server): State<Arc<SyncServer>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(handle) = server.builtin_handles.slack() else {
        return Reply::Refused(
            StatusCode::NOT_FOUND,
            "this host serves no checked Slack pack",
        )
        .into_response();
    };
    let timestamp = header(&headers, "x-slack-request-timestamp");
    let signature = header(&headers, "x-slack-signature");
    let vault = Arc::clone(server.vault());
    answer(move || slack_event(&vault, &handle, timestamp, signature, &body)).await
}

/// `POST /v1/hooks/line/webhook`: one signed Messaging API delivery.
async fn line_webhook(
    State(server): State<Arc<SyncServer>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(handle) = server.builtin_handles.line() else {
        return Reply::Refused(
            StatusCode::NOT_FOUND,
            "this host serves no checked LINE pack",
        )
        .into_response();
    };
    let signature = header(&headers, "x-line-signature");
    let vault = Arc::clone(server.vault());
    answer(move || line_events(&vault, &handle, signature, &body)).await
}

async fn answer(work: impl FnOnce() -> oneiron::Result<Reply> + Send + 'static) -> Response {
    match tokio::task::spawn_blocking(work).await {
        Ok(Ok(reply)) => reply.into_response(),
        Ok(Err(error)) => {
            tracing::warn!(%error, "provider webhook failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

fn slack_event(
    vault: &Vault,
    handle: &SlackHandle,
    timestamp: Option<String>,
    signature: Option<String>,
    body: &[u8],
) -> oneiron::Result<Reply> {
    let now = unix_now();
    let unsigned = Reply::Refused(
        StatusCode::UNAUTHORIZED,
        "the request is not signed by Slack",
    );
    let (Some(timestamp), Some(signature)) = (timestamp, signature) else {
        return Ok(unsigned);
    };
    if timestamp
        .parse::<u64>()
        .map_or(true, |sent| now.abs_diff(sent) > SLACK_MAX_SKEW_SECS)
    {
        return Ok(unsigned);
    }
    let Some(expected) = signature.strip_prefix("v0=").and_then(decode_hex) else {
        return Ok(unsigned);
    };
    let signed = [
        b"v0:".as_slice(),
        timestamp.as_bytes(),
        b":".as_slice(),
        body,
    ];
    if !hmac_matches(vault, &handle.signing_secret, &signed, &expected)? {
        return Ok(unsigned);
    }
    let Some(checked) = vault.checked_builtin_channel(SLACK_CHANNEL, SLACK_CONNECTION)? else {
        return Ok(Reply::Refused(
            StatusCode::NOT_FOUND,
            "this host serves no checked Slack pack",
        ));
    };
    let Ok(delivery) = serde_json::from_slice::<Value>(body) else {
        return Ok(Reply::Refused(
            StatusCode::BAD_REQUEST,
            "the body is not JSON",
        ));
    };
    match text(&delivery, "type") {
        Some("url_verification") => {
            return Ok(Reply::Challenge(
                text(&delivery, "challenge").unwrap_or_default().to_owned(),
            ));
        }
        Some("event_callback") => {}
        _ => return Ok(Reply::Ack),
    }
    let team_id = text(&delivery, "team_id").unwrap_or_default();
    if team_id != handle.team_id || checked.check.provider_account.as_deref() != Some(team_id) {
        tracing::info!(
            team_id,
            "a Slack event from a workspace the check did not bind"
        );
        return Ok(Reply::Ack);
    }
    let Some(event) = delivery.get("event") else {
        return Ok(Reply::Ack);
    };
    // An app mention or a direct message from a person; never a bot's own
    // message or an edit, so the agent never answers itself.
    let kind = text(event, "type");
    let direct = kind == Some("message") && text(event, "channel_type") == Some("im");
    if !(kind == Some("app_mention") || direct)
        || event.get("bot_id").is_some()
        || event.get("subtype").is_some()
    {
        return Ok(Reply::Ack);
    }
    let (Some(event_id), Some(channel_id), Some(user_id)) = (
        text(&delivery, "event_id"),
        text(event, "channel"),
        text(event, "user"),
    ) else {
        return Ok(Reply::Ack);
    };
    let enterprise_id = text(&delivery, "enterprise_id").filter(|id| !id.is_empty());
    let workspace_ref = SlackSharedPresenceAdapter::workspace_ref(team_id, enterprise_id)?;
    let personas = vault.slack_workspace_personas(&workspace_ref)?;
    let Some(persona) = receiving_persona(&personas, &delivery) else {
        tracing::info!(
            workspace = %workspace_ref,
            "a Slack event for a workspace with no agent persona; nothing to route"
        );
        return Ok(Reply::Ack);
    };
    let payload_ref = vault.archive_provider_event(SLACK_CHANNEL, event_id, body, now)?;
    let inbound = SlackProviderInbound {
        provider_event_id: event_id.to_owned(),
        workspace_id: team_id.to_owned(),
        enterprise_id: enterprise_id.map(str::to_owned),
        channel_id: channel_id.to_owned(),
        user_id: user_id.to_owned(),
        persona_handle: persona.to_owned(),
        payload_ref: Some(payload_ref),
        received_at: now,
    };
    admit(
        vault,
        handle
            .adapter
            .parse_inbound(ChannelIdentityProviderInbound::Slack(inbound)),
        now,
    )?;
    Ok(Reply::Ack)
}

/// The persona a Slack event goes to (Engine ruling 10-17). One persona in
/// the workspace takes it. With several, the one the event's addressed bot
/// or app names, else the earliest, and the choice is logged; an addressed
/// message is never dropped for a tie.
fn receiving_persona<'p>(personas: &'p [String], delivery: &Value) -> Option<&'p str> {
    if personas.len() > 1 {
        let addressed: Vec<String> = delivery
            .get("authorizations")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|authorization| text(authorization, "user_id"))
            .chain(text(delivery, "api_app_id"))
            .map(str::to_ascii_lowercase)
            .collect();
        if let Some(persona) = personas.iter().find(|persona| addressed.contains(persona)) {
            return Some(persona);
        }
        tracing::info!(
            persona = %personas[0],
            candidates = personas.len(),
            "several Slack personas in one workspace; the event goes to the earliest"
        );
    }
    personas.first().map(String::as_str)
}

fn line_events(
    vault: &Vault,
    handle: &LineHandle,
    signature: Option<String>,
    body: &[u8],
) -> oneiron::Result<Reply> {
    let now = unix_now();
    let unsigned = Reply::Refused(
        StatusCode::UNAUTHORIZED,
        "the request is not signed by LINE",
    );
    let Some(expected) = signature.and_then(|signature| {
        base64::engine::general_purpose::STANDARD
            .decode(signature.trim())
            .ok()
    }) else {
        return Ok(unsigned);
    };
    if !hmac_matches(vault, &handle.channel_secret, &[body], &expected)? {
        return Ok(unsigned);
    }
    let Some(checked) = vault.checked_builtin_channel(LINE_CHANNEL, LINE_CONNECTION)? else {
        return Ok(Reply::Refused(
            StatusCode::NOT_FOUND,
            "this host serves no checked LINE pack",
        ));
    };
    let Ok(delivery) = serde_json::from_slice::<Value>(body) else {
        return Ok(Reply::Refused(
            StatusCode::BAD_REQUEST,
            "the body is not JSON",
        ));
    };
    let destination = text(&delivery, "destination").unwrap_or_default();
    if destination != handle.destination
        || checked.check.provider_account.as_deref() != Some(destination)
    {
        tracing::info!("a LINE delivery for a bot the check did not bind");
        return Ok(Reply::Ack);
    }
    // A signed empty `events` is LINE's own webhook test.
    for event in delivery
        .get("events")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let message = event.get("message");
        if text(event, "type") != Some("message")
            || message.and_then(|message| text(message, "type")) != Some("text")
        {
            continue;
        }
        let (Some(event_id), Some(user_id)) = (
            text(event, "webhookEventId"),
            event
                .get("source")
                .and_then(|source| text(source, "userId")),
        ) else {
            continue;
        };
        // The event as LINE sent it, reply token included, beside the bot
        // it was for: a later reply path reads the token back from here.
        let kept = serde_json::to_vec(&serde_json::json!({
            "destination": destination,
            "event": event,
        }))
        .map_err(|_| oneiron::Error::InvariantViolation("LINE event did not encode"))?;
        let payload_ref = vault.archive_provider_event(LINE_CHANNEL, event_id, &kept, now)?;
        let inbound = LineOfficialAccountInbound {
            provider_event_id: event_id.to_owned(),
            destination: destination.to_owned(),
            source_user_id: user_id.to_owned(),
            reply_token: None,
            payload_ref: Some(payload_ref),
            received_at: now,
        };
        admit(
            vault,
            handle
                .adapter
                .parse_inbound(ChannelIdentityProviderInbound::Line(inbound)),
            now,
        )?;
    }
    Ok(Reply::Ack)
}

/// Queues one parsed event. An event the adapter or the routing boundary
/// refuses is logged and acknowledged: the provider resending it changes
/// nothing.
fn admit(
    vault: &Vault,
    parsed: oneiron::Result<InboundSurfaceEventInput>,
    now: u64,
) -> oneiron::Result<()> {
    let input = match parsed {
        Ok(input) => input,
        Err(error) => {
            tracing::info!(%error, "a provider event the adapter does not take");
            return Ok(());
        }
    };
    match vault.enqueue_inbound_surface_event(input, now) {
        Ok(SurfaceEventAdmission::Accepted(_)) => {}
        Ok(SurfaceEventAdmission::Rejected(receipt)) => {
            tracing::info!(?receipt, "a provider event the routing boundary rejected");
        }
        Err(oneiron::Error::InvalidConfig(reason)) => {
            tracing::info!(%reason, "a provider event the routing boundary refused");
        }
        Err(error) => return Err(error),
    }
    Ok(())
}

/// Whether `expected` is the HMAC-SHA256 of `message` under the stored
/// secret. The value is read through the credential door for the declared
/// effector and never leaves this closure.
fn hmac_matches(
    vault: &Vault,
    secret: &PackSetupSecret,
    message: &[&[u8]],
    expected: &[u8],
) -> oneiron::Result<bool> {
    let mut matched = false;
    vault.inject_secret_at_door(&secret.name, &secret.effector, &mut |value: &[u8]| {
        let mut mac = Hmac::<Sha256>::new_from_slice(value.trim_ascii()).map_err(|_| {
            oneiron::Error::InvalidConfig("the stored signing secret is unusable".to_owned())
        })?;
        for part in message {
            mac.update(part);
        }
        matched = mac.verify_slice(expected).is_ok();
        Ok(())
    })?;
    Ok(matched)
}

fn header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn text<'v>(value: &'v Value, name: &str) -> Option<&'v str> {
    value.get(name).and_then(Value::as_str)
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(text.get(at..at + 2)?, 16).ok())
        .collect()
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}
