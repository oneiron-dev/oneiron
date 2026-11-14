//! The public QR page a sealed document's certificate names (ARCH-0064a
//! section 6, [SGN-05]): `/esign/verify#<capability>`. The capability rides
//! the fragment, so the page request carries none. The page scrubs it from
//! the address bar and posts it only in the `x-oneiron-esign-qr-capability`
//! header of `/esign/verify/report`, which answers the vault's projection
//! ([`oneiron::blob_artifact::esign::EsignQrPage`]): metadata, each item's
//! hash and its seal-time validation. The PDF stays behind a separate
//! possession factor (ARCH-0064a section 6): each party's own signing link,
//! which reads the sealed copy after the seal, and the page says so. Only
//! when the vault owner turned on the document's QR PDF download does
//! `/esign/verify/pdf` serve the sealed item, under the same header; the
//! page then offers it. The page says in two separate sentences that a
//! reader without the signer's trust root and a changed document are
//! different facts (ARCH-0064a section 9). Every response is noindex,
//! no-referrer and no-store. An unusable capability gets one refusal,
//! counted in the wire window under no caller, and no call is refused for
//! its rate.
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
/// The sealed PDF the page downloads, when the owner allows it.
const QR_PDF_PATH: &str = "/esign/verify/pdf";
/// The header the page sends its capability in.
const QR_CAPABILITY_HEADER: &str = "x-oneiron-esign-qr-capability";

/// Keyless, as the signing ceremony's routes are: the capability is checked
/// in the vault on each report.
pub(super) fn public_routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route(QR_PAGE_PATH, get(page))
        .route(QR_REPORT_PATH, post(report))
        .route(QR_PDF_PATH, post(pdf))
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

/// The capability in the request's header, when it has the capability's
/// form.
fn capability(headers: &HeaderMap) -> Option<EsignQrCapability> {
    headers
        .get(QR_CAPABILITY_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|raw| EsignQrCapability::parse(raw).ok())
}

async fn report(State(server): State<Arc<SyncServer>>, headers: HeaderMap) -> Response {
    let Some(token) = capability(&headers) else {
        return refused(&server, QR_REPORT_PATH);
    };
    let vault = Arc::clone(&server.vault);
    match tokio::task::spawn_blocking(move || vault.esign_qr_page(&token)).await {
        Ok(Ok(page)) => Json(page).into_response(),
        Ok(Err(_)) | Err(_) => refused(&server, QR_REPORT_PATH),
    }
}

/// The item a PDF download asks for, by position.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct QrPdfBody {
    item: usize,
}

/// The sealed PDF of one item, as an attachment, when the capability is
/// usable and the owner turned on the document's QR PDF download; the one
/// refusal otherwise.
async fn pdf(
    State(server): State<Arc<SyncServer>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let (Some(token), Ok(QrPdfBody { item })) = (
        capability(&headers),
        serde_json::from_slice::<QrPdfBody>(&body),
    ) else {
        return refused(&server, QR_PDF_PATH);
    };
    let vault = Arc::clone(&server.vault);
    match tokio::task::spawn_blocking(move || vault.esign_qr_sealed_pdf(&token, item)).await {
        Ok(Ok(bytes)) => {
            let disposition = format!("attachment; filename=sealed-document-{}.pdf", item + 1);
            (
                [
                    (header::CONTENT_TYPE, "application/pdf".to_owned()),
                    (header::CONTENT_DISPOSITION, disposition),
                    (
                        header::CONTENT_SECURITY_POLICY,
                        "sandbox; default-src 'none'".to_owned(),
                    ),
                ],
                bytes,
            )
                .into_response()
        }
        Ok(Err(_)) | Err(_) => refused(&server, QR_PDF_PATH),
    }
}

/// One answer for every unusable capability: unknown, revoked, expired or
/// erased alike, and on `/esign/verify/pdf` a document whose QR PDF download
/// is off. Each refusal counts in the wire window beside its route's call,
/// under no caller, so guesses at a capability ask the call-volume question
/// past the per-verb row; none is refused for its rate.
fn refused(server: &SyncServer, path: &str) -> Response {
    let _ = server
        .wire_telemetry
        .record_capability_refusal(&format!("POST {path}"), oneiron_vault_contract::now_ts());
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
