//! The public QR page a sealed document's certificate names (ARCH-0064a
//! section 6, [SGN-05]): `/esign/verify#<capability>`. The capability rides
//! the fragment, so the page request carries none. The page scrubs it from
//! the address bar and posts it only in the `x-oneiron-esign-qr-capability`
//! header of `/esign/verify/report`, which answers the vault's projection
//! ([`oneiron::blob_artifact::esign::EsignQrPage`]): metadata, each item's
//! hash and its seal-time validation, never the PDF. The page says in two
//! separate sentences that a reader without the signer's trust root and a
//! changed document are different facts (ARCH-0064a section 9). Every
//! response is noindex, no-referrer and no-store. An unusable capability
//! gets one refusal, and no call is refused for its rate.
use crate::server::SyncServer;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use oneiron::blob_artifact::esign::EsignQrCapability;
use std::sync::Arc;

/// The QR page's path at the host's public origin.
pub(crate) const QR_PAGE_PATH: &str = "/esign/verify";
/// The report the page reads.
const QR_REPORT_PATH: &str = "/esign/verify/report";
/// The header the page sends its capability in.
const QR_CAPABILITY_HEADER: &str = "x-oneiron-esign-qr-capability";

/// Keyless, as the signing ceremony's routes are: the capability is checked
/// in the vault on each report.
pub(super) fn public_routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route(QR_PAGE_PATH, get(page))
        .route(QR_REPORT_PATH, post(report))
        .layer(axum::middleware::from_fn(private_response))
}

async fn page() -> Response {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let script = include_str!("esign_qr/page.js");
    let digest =
        base64::engine::general_purpose::STANDARD.encode(Sha256::digest(script.as_bytes()));
    let csp = format!(
        "default-src 'none'; script-src 'sha256-{digest}'; connect-src 'self'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    );
    let html = format!(
        "<!doctype html><html lang=en><meta charset=utf-8><meta name=referrer content=no-referrer><meta name=robots content=noindex><title>Document verification</title><main><h1>Document verification</h1><p id=status></p><dl id=report></dl><div id=reading></div></main><script>{script}</script></html>"
    );
    (
        [(header::CONTENT_SECURITY_POLICY, csp)],
        axum::response::Html(html),
    )
        .into_response()
}

async fn report(State(server): State<Arc<SyncServer>>, headers: HeaderMap) -> Response {
    let Some(token) = headers
        .get(QR_CAPABILITY_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|raw| EsignQrCapability::parse(raw).ok())
    else {
        return refused();
    };
    let vault = Arc::clone(&server.vault);
    match tokio::task::spawn_blocking(move || vault.esign_qr_page(&token)).await {
        Ok(Ok(page)) => Json(page).into_response(),
        Ok(Err(_)) | Err(_) => refused(),
    }
}

/// One answer for every unusable capability: unknown, revoked, expired or
/// erased alike.
fn refused() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error":{"code":"verification_unavailable"}})),
    )
        .into_response()
}

async fn private_response(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("x-robots-tag"),
        HeaderValue::from_static("noindex, nofollow"),
    );
    response
}
