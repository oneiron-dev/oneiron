//! Public session-less signing lens. The capability is in POST, never the URL.
use crate::server::SyncServer;
mod presentation;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use oneiron::blob_artifact::esign::{EsignCapability, SigningAction};
use serde::Deserialize;
use std::sync::Arc;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SigningRequest {
    token: String,
    action: SigningAction,
}
pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/sign", get(page))
        .route("/sign/action", post(action))
        .route("/sign/pdf", post(pdf))
        .route("/sign/image", post(image))
        .route("/sign/preview", post(presentation::preview))
        .route("/sign/signature", post(presentation::signature))
        .route("/sign/editor", get(presentation::editor))
        .route("/sign/layout", post(presentation::layout))
        .route(
            "/sign/geometry",
            post(presentation::upload_geometry).layer(DefaultBodyLimit::max(16 * 1024 * 1024)),
        )
        .route("/sign/field-renderer.js", get(presentation::field_script))
        .route("/sign/editor.js", get(presentation::editor_script))
        .layer(DefaultBodyLimit::max(3 * 1024 * 1024))
        .layer(axum::middleware::from_fn(private_response))
}
async fn action(
    State(server): State<Arc<SyncServer>>,
    headers: HeaderMap,
    peer: Result<
        axum::extract::ConnectInfo<std::net::SocketAddr>,
        axum::extract::rejection::ExtensionRejection,
    >,
    Json(request): Json<SigningRequest>,
) -> Response {
    let token = match EsignCapability::parse(&request.token) {
        Ok(token) => token,
        Err(_) => return refused(),
    };
    // Proxy forwarding headers are not an authenticated IP source. Do not
    // copy attacker-supplied X-Forwarded-For into the legal audit trail.
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .filter(|v| v.len() <= 1024)
        .map(str::to_owned);
    let Ok(axum::extract::ConnectInfo(peer)) = peer else {
        return unavailable();
    };
    let ip = Some(peer.ip().to_string());
    match server
        .vault
        .execute_signing_action(&token, &request.action, ip, ua)
    {
        Ok(outcome) => (
            [
                (header::CACHE_CONTROL, "no-store"),
                (header::REFERRER_POLICY, "no-referrer"),
                (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            ],
            Json(outcome),
        )
            .into_response(),
        Err(_) => refused(),
    }
}
fn refused() -> Response {
    (
        StatusCode::FORBIDDEN,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::REFERRER_POLICY, "no-referrer"),
        ],
        Json(serde_json::json!({"error":{"code":"signing_unavailable"}})),
    )
        .into_response()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PdfRequest {
    token: String,
    item: usize,
}
async fn pdf(
    State(server): State<Arc<SyncServer>>,
    headers: HeaderMap,
    peer: Result<
        axum::extract::ConnectInfo<std::net::SocketAddr>,
        axum::extract::rejection::ExtensionRejection,
    >,
    Json(request): Json<PdfRequest>,
) -> Response {
    let token = match EsignCapability::parse(&request.token) {
        Ok(t) => t,
        Err(_) => return refused(),
    };
    let Ok(axum::extract::ConnectInfo(peer)) = peer else {
        return unavailable();
    };
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .filter(|v| v.len() <= 1024)
        .map(str::to_owned);
    match server.vault.esign_pdf_for_capability(
        &token,
        request.item,
        Some(peer.ip().to_string()),
        ua,
    ) {
        Ok(bytes) => {
            let mut response = (
                [
                    (header::CONTENT_TYPE, "application/pdf"),
                    (
                        header::CONTENT_DISPOSITION,
                        "attachment; filename=document.pdf",
                    ),
                    (header::CACHE_CONTROL, "no-store"),
                    (header::REFERRER_POLICY, "no-referrer"),
                    (
                        header::CONTENT_SECURITY_POLICY,
                        "sandbox; default-src 'none'",
                    ),
                    (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
                ],
                bytes,
            )
                .into_response();
            if let Ok(name) = axum::http::HeaderValue::from_str(&format!(
                "attachment; filename=document-{}.pdf",
                request.item + 1
            )) {
                response
                    .headers_mut()
                    .insert(header::CONTENT_DISPOSITION, name);
            }
            response
        }
        Err(_) => refused(),
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImageRequest {
    token: String,
    png_or_jpeg_base64: String,
}
async fn image(
    State(server): State<Arc<SyncServer>>,
    Json(request): Json<ImageRequest>,
) -> Response {
    use base64::Engine;
    let token = match EsignCapability::parse(&request.token) {
        Ok(t) => t,
        Err(_) => return refused(),
    };
    let bytes = match base64::engine::general_purpose::STANDARD.decode(&request.png_or_jpeg_base64)
    {
        Ok(b) => b,
        Err(_) => return refused(),
    };
    match server.vault.upload_esign_signature_image(&token, &bytes) {
        Ok(image_ref) => (
            [
                (header::CACHE_CONTROL, "no-store"),
                (header::REFERRER_POLICY, "no-referrer"),
            ],
            Json(serde_json::json!({"image_ref":image_ref})),
        )
            .into_response(),
        Err(_) => refused(),
    }
}
async fn page() -> Response {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let script = [
        include_str!("esign/field-renderer.js"),
        include_str!("esign/ceremony.js"),
    ]
    .join("\n");
    let digest =
        base64::engine::general_purpose::STANDARD.encode(Sha256::digest(script.as_bytes()));
    let csp = format!(
        "default-src 'none'; script-src 'sha256-{digest}'; connect-src 'self'; style-src 'unsafe-inline'; img-src blob:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    );
    let html = format!(
        "<!doctype html><html lang=en><meta charset=utf-8><meta name=referrer content=no-referrer><title>Signing request</title><main><h1 id=title>Signing request</h1><p id=status></p><section id=fields></section><section id=preview></section><select id=item aria-label=Document></select><button id=download>Download PDF</button><label><input id=consent type=checkbox>I agree to sign this document.</label><button id=complete>Complete</button><button id=reject>Reject</button></main><script>{script}</script></html>"
    );
    (
        [
            (header::CONTENT_SECURITY_POLICY, csp),
            (header::CACHE_CONTROL, "no-store".into()),
            (header::REFERRER_POLICY, "no-referrer".into()),
        ],
        axum::response::Html(html),
    )
        .into_response()
}

async fn private_response(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        axum::http::HeaderValue::from_static("no-referrer"),
    );
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static("nosniff"),
    );
    response
}

fn unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({"error":{"code":"signing_transport_unavailable"}})),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use tower::ServiceExt;
    #[tokio::test]
    async fn sessionless_page_and_refusals_never_cache_or_echo_capabilities() {
        let dir = tempfile::tempdir().unwrap();
        let vault =
            Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
        let server =
            Arc::new(SyncServer::new(vault, crate::config::SyncServerConfig::default()).unwrap());
        let app = routes().with_state(server);
        let page = app
            .clone()
            .oneshot(Request::builder().uri("/sign").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(page.status(), StatusCode::OK);
        assert_eq!(page.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(page.headers()[header::REFERRER_POLICY], "no-referrer");
        assert!(page.headers().contains_key(header::CONTENT_SECURITY_POLICY));
        assert!(!page.headers().contains_key(header::SET_COOKIE));
        for (path, body, status) in [
            (
                "/sign/action",
                serde_json::json!({"token":"11".repeat(32),"action":{"action":"load"}}).to_string(),
                StatusCode::FORBIDDEN,
            ),
            (
                "/sign/pdf",
                serde_json::json!({"token":"11".repeat(32),"item":0}).to_string(),
                StatusCode::FORBIDDEN,
            ),
            (
                "/sign/image",
                serde_json::json!({"token":"11".repeat(32),"png_or_jpeg_base64":"invalid"})
                    .to_string(),
                StatusCode::FORBIDDEN,
            ),
            ("/sign/action", "{".to_owned(), StatusCode::BAD_REQUEST),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(path)
                        .extension(axum::extract::ConnectInfo(
                            "127.0.0.1:12345".parse::<std::net::SocketAddr>().unwrap(),
                        ))
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), status);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert_eq!(response.headers()[header::REFERRER_POLICY], "no-referrer");
            let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
            assert!(!String::from_utf8_lossy(&bytes).contains(&"11".repeat(32)));
        }
    }
    #[tokio::test]
    async fn forwarded_headers_cannot_replace_the_signing_transport_peer() {
        let dir = tempfile::tempdir().unwrap();
        let vault =
            Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
        let server =
            Arc::new(SyncServer::new(vault, crate::config::SyncServerConfig::default()).unwrap());
        let app = routes().with_state(server);
        for path in ["/sign/action", "/sign/pdf", "/sign/preview"] {
            let body = if path == "/sign/action" {
                serde_json::json!({"token":"11".repeat(32), "action":{"action":"load"}})
            } else {
                serde_json::json!({"token":"11".repeat(32), "item":0})
            };
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(path)
                        .header(header::CONTENT_TYPE, "application/json")
                        .header("x-forwarded-for", "192.0.2.7")
                        .header("forwarded", "for=192.0.2.7")
                        .body(Body::from(body.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "{path}");
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert_eq!(response.headers()[header::REFERRER_POLICY], "no-referrer");
            let body: serde_json::Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap())
                    .unwrap();
            assert_eq!(
                body,
                serde_json::json!({"error":{"code":"signing_transport_unavailable"}})
            );
        }
    }

    #[tokio::test]
    async fn geometry_upload_accepts_the_full_renderer_input_budget() {
        let dir = tempfile::tempdir().unwrap();
        let vault =
            Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
        let server =
            Arc::new(SyncServer::new(vault, crate::config::SyncServerConfig::default()).unwrap());
        let app = routes().with_state(server);
        let mut pdf = b"%PDF-1.7\n".to_vec();
        let mut offsets = Vec::new();
        for (index, body) in [
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] /Contents 4 0 R >>",
            "<< /Length 0 >>\nstream\nendstream",
        ]
        .into_iter()
        .enumerate()
        {
            offsets.push(pdf.len());
            pdf.extend_from_slice(format!("{} 0 obj\n{}\nendobj\n", index + 1, body).as_bytes());
        }
        offsets.push(pdf.len());
        pdf.extend_from_slice(b"5 0 obj\n(");
        pdf.extend(std::iter::repeat_n(b'x', 4 * 1024 * 1024));
        pdf.extend_from_slice(b")\nendobj\n");
        let xref = pdf.len();
        pdf.extend_from_slice(b"xref\n0 6\n0000000000 65535 f \n");
        for offset in offsets {
            pdf.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
        }
        pdf.extend_from_slice(
            format!("trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n").as_bytes(),
        );
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/sign/geometry")
                    .header(header::CONTENT_TYPE, "application/pdf")
                    .body(Body::from(pdf))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(body["pages"].as_array().unwrap().len(), 1);
        assert_eq!(
            body["pages"][0]["crop"],
            serde_json::json!([0.0, 0.0, 100.0, 100.0])
        );
    }
}
