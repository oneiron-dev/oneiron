//! The public one-click unsubscribe door a bulk campaign email's
//! List-Unsubscribe names (ARCH-0059 #opt-out; RFC 8058; FIX
//! [CAMPAIGN-BULK-SEND-MODE] PR 2):
//! `POST /unsubscribe/one-click/{campaign}/{person}/{mac}` with the body
//! `List-Unsubscribe=One-Click`.
//!
//! Keyless, as the signing ceremony's doors are: the link's mac, checked in
//! the vault on each call, is the authority, and whoever holds the link may
//! redeem it, which is what RFC 8058 one-click means. A verified POST writes
//! the member's email suppression before it answers 200, and a repeat
//! answers 200 again; a link that does not verify answers 404, writes
//! nothing and counts as a capability refusal in the wire window. A GET
//! never unsubscribes, because mail scanners fetch links: it answers a plain
//! page whose one button posts the same body. No call is refused for its
//! rate. Every response is no-store, no-referrer and noindex.

use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use oneiron::campaign::one_click_unsubscribe::OneClickUnsubscribeOutcome;

use crate::server::SyncServer;

/// The link's route; its prefix is
/// [`oneiron::campaign::one_click_unsubscribe::ONE_CLICK_UNSUBSCRIBE_PATH`],
/// the path the vault mints links under.
const ONE_CLICK_ROUTE: &str = "/unsubscribe/one-click/{campaign}/{person}/{mac}";

/// The RFC 8058 body is one short form field; anything larger is refused
/// before the handler reads it.
const MAX_BODY_BYTES: usize = 4 * 1024;

/// The RFC 8058 form field, its one value, and the two as a urlencoded
/// pair.
const ONE_CLICK_FIELD: &str = "List-Unsubscribe";
const ONE_CLICK_VALUE: &str = "One-Click";
const ONE_CLICK_PAIR: &str = "List-Unsubscribe=One-Click";

/// The link's three path parts, as the vault spelled them.
type LinkParts = (String, String, String);

pub(super) fn public_routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route(ONE_CLICK_ROUTE, get(page).post(redeem))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(axum::middleware::from_fn(super::esign_qr::private_response))
}

/// Installs this host's public origin on its vault, so bulk campaign email
/// names this door: `oauth_resource_indicator`
/// (`--oauth-resource-indicator`), the https base every public link this
/// host sends is built on. With none, or one that is not an https base, the
/// vault mints no link and bulk campaign email blocks.
pub(crate) fn install_one_click_unsubscribe_origin(server: &SyncServer) {
    let Some(origin) = server
        .config
        .oauth_resource_indicator
        .as_deref()
        .map(str::trim)
        .filter(|origin| !origin.is_empty())
    else {
        tracing::info!(
            "no public origin (oauth_resource_indicator), so no one-click unsubscribe link is minted and bulk campaign email blocks"
        );
        return;
    };
    if let Err(error) = server.vault.install_one_click_unsubscribe_origin(origin) {
        tracing::warn!(
            kind = ?error.kind(),
            "the public origin did not install for one-click unsubscribe links, so bulk campaign email blocks"
        );
    }
}

/// A plain page whose one button posts the RFC 8058 body to this link, when
/// the link verifies; 404 otherwise. Nothing is written.
async fn page(
    State(server): State<Arc<SyncServer>>,
    Path((campaign, person, mac)): Path<LinkParts>,
) -> Response {
    let vault = Arc::clone(&server.vault);
    let verifies = tokio::task::spawn_blocking(move || {
        vault.one_click_unsubscribe_verifies(&campaign, &person, &mac)
    })
    .await;
    match verifies {
        Ok(Ok(true)) => {
            let csp = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'".to_owned();
            let html = format!(
                "<!doctype html><html lang=en><meta charset=utf-8><meta name=referrer content=no-referrer><meta name=robots content=noindex><title>Unsubscribe</title><main><h1>Unsubscribe</h1><p>Stop this list's email to you.</p><form method=post><input type=hidden name={ONE_CLICK_FIELD} value={ONE_CLICK_VALUE}><button type=submit>Unsubscribe</button></form></main></html>"
            );
            super::first_party_html::isolated_html(csp, html)
        }
        Ok(Ok(false)) => refused(&server, "GET").await,
        Ok(Err(_)) | Err(_) => unavailable(),
    }
}

/// RFC 8058 one-click: a verified link with the one-click body writes the
/// member's email suppression, then answers 200.
async fn redeem(
    State(server): State<Arc<SyncServer>>,
    Path((campaign, person, mac)): Path<LinkParts>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_one_click_body(&headers, &body) {
        return (
            StatusCode::BAD_REQUEST,
            "an RFC 8058 one-click unsubscribe posts List-Unsubscribe=One-Click",
        )
            .into_response();
    }
    let vault = Arc::clone(&server.vault);
    let outcome = tokio::task::spawn_blocking(move || {
        vault.redeem_one_click_unsubscribe(&campaign, &person, &mac)
    })
    .await;
    match outcome {
        Ok(Ok(OneClickUnsubscribeOutcome::Unsubscribed)) => (
            StatusCode::OK,
            "You are unsubscribed: this list sends you no more email.",
        )
            .into_response(),
        Ok(Ok(OneClickUnsubscribeOutcome::NotRecognized)) => refused(&server, "POST").await,
        Ok(Err(error)) => {
            tracing::warn!(
                kind = ?error.kind(),
                "a verified one-click unsubscribe did not write; the sender may post again"
            );
            unavailable()
        }
        Err(_) => unavailable(),
    }
}

/// Whether `body` carries the RFC 8058 field `List-Unsubscribe=One-Click`,
/// as a form-urlencoded pair or as a multipart/form-data part.
fn is_one_click_body(headers: &HeaderMap, body: &[u8]) -> bool {
    let Ok(body) = std::str::from_utf8(body) else {
        return false;
    };
    let multipart = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .trim_start()
                .to_ascii_lowercase()
                .starts_with("multipart/form-data")
        });
    if multipart {
        return body
            .split(&format!("name=\"{ONE_CLICK_FIELD}\""))
            .skip(1)
            .any(|part| {
                part.split_once("\r\n\r\n")
                    .and_then(|(_, rest)| rest.split("\r\n").next())
                    .is_some_and(|value| value.trim() == ONE_CLICK_VALUE)
            });
    }
    body.trim().split('&').any(|pair| pair == ONE_CLICK_PAIR)
}

/// One answer for every link that does not verify: malformed, minted by no
/// key of this vault, or on a vault with no key. Each counts in the wire
/// window under no caller, so guesses at a mac ask the call-volume question;
/// none is refused for its rate. The count waits on the blocking pool, as the
/// wire observer's does.
async fn refused(server: &Arc<SyncServer>, method: &'static str) -> Response {
    crate::wire_telemetry::record_on_blocking_pool(server, move |telemetry, now| {
        telemetry.record_capability_refusal(&format!("{method} {ONE_CLICK_ROUTE}"), now)
    })
    .await;
    (
        StatusCode::NOT_FOUND,
        "this unsubscribe link is not known here",
    )
        .into_response()
}

/// The vault did not answer: the sender may post again.
fn unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "the unsubscribe could not be recorded now; try again",
    )
        .into_response()
}
