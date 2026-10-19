//! Session-less signing ceremony. The public link carries the capability in its
//! fragment (`/sign#<token>`); after loading, the client scrubs it and sends it
//! only in the `x-oneiron-esign-capability` header of each ceremony POST, which
//! the vault admits before the body is read (`ingress`, FIX 3808). A call
//! that also presents a vault credential is classed by it: an agent's Complete
//! is an automated sign act, whoever's link it holds.
use crate::server::SyncServer;
pub(crate) mod delivery_outbox;
mod editor_budget;
pub(crate) mod hold_worker;
mod ingress;
mod presentation;
#[cfg(unix)]
pub(crate) mod seal_worker;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode, header, request::Parts};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use ingress::SigningIngress;
use oneiron::blob_artifact::esign::{EsignSigningImageView, SigningCaller};
use std::sync::Arc;
pub(super) fn editor_routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/sign/layout", post(presentation::layout))
        .route(
            "/sign/geometry",
            post(presentation::upload_geometry).layer(DefaultBodyLimit::max(16 * 1024 * 1024)),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            editor_budget::EditorBudget::new(),
            editor_budget::admit,
        ))
        .route("/sign/editor", get(presentation::editor))
        .route("/sign/field-renderer.js", get(presentation::field_script))
        .route("/sign/editor.js", get(presentation::editor_script))
        .layer(DefaultBodyLimit::max(3 * 1024 * 1024))
        .layer(axum::middleware::from_fn(private_response))
}

/// Only the signing ceremony bypasses the hosted device-lease gate. Every
/// action and document read still checks the bearer capability in the vault,
/// from its header and before its body. An admitted body has no size refusal:
/// it spools whole under the disk floor and its size is the `[limits]
/// esign_body_bytes` row, so no `DefaultBodyLimit` sits on these routes.
pub(super) fn public_routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/sign", get(page))
        // A signing link is `/sign#<token>`: a capability in the request path
        // reaches server and proxy logs (F37), so a path token is refused,
        // never served.
        .route("/sign/{token}", get(path_token_refused))
        .route("/sign/action", post(action))
        .route("/sign/pdf", post(pdf))
        .route("/sign/image", post(image))
        .route("/sign/preview", post(presentation::preview))
        .route("/sign/signature", post(presentation::signature))
        .layer(axum::middleware::from_fn(private_response))
}
async fn action(
    State(server): State<Arc<SyncServer>>,
    SigningIngress { token, admitted }: SigningIngress,
    parts: Parts,
    peer: NetworkPeer,
    local_peer: LocalPeer,
    body: Body,
) -> Response {
    let headers = &parts.headers;
    // Proxy forwarding headers are not an authenticated IP source. Do not
    // copy attacker-supplied X-Forwarded-For into the legal audit trail.
    // The user agent is kept whole, however long (Rule 5): the header's own
    // bound is the HTTP codec's.
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let Ok(ip) = signing_peer_ip(peer, local_peer) else {
        return unavailable();
    };
    let Ok(caller) = signing_caller(&parts, &server) else {
        return refused();
    };
    let request: ingress::ActionBody =
        match ingress::payload(&server, admitted, headers, body).await {
            Ok(request) => request,
            Err(response) => return response,
        };
    match server
        .vault
        .execute_signing_action_as(&token, &request.action, caller, ip, ua)
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
/// Who the signing call shows itself to be. A browser signer sends no
/// credential (the page posts with `credentials: "omit"`), so the capability
/// stands alone; a call that presents one is classed by the actor class its
/// credential binds, and only `human` is a person. A credential that does not
/// verify is refused. On a managed vault a call its supervisor attested for
/// the vault's owner, with no credential of its own, is that person while
/// the vault records him as its live owner; otherwise its capability stands
/// alone, as a browser signer's does.
fn signing_caller(request: &Parts, server: &SyncServer) -> Result<SigningCaller, ()> {
    let headers = &request.headers;
    if !headers.contains_key(header::AUTHORIZATION) {
        let owner =
            crate::auth::attested_owner(&request.extensions, server).is_some_and(|holder| {
                crate::auth::CoreAuth::for_attested_owner(holder, server).is_ok()
            });
        return Ok(if owner {
            SigningCaller::Person
        } else {
            SigningCaller::Bearer
        });
    }
    let auth = crate::auth::CoreAuth::for_managed_request(
        headers,
        &request.extensions,
        crate::auth::request_path(request),
        server,
    )
    .unwrap_or_else(|| {
        crate::auth::CoreAuth::from_headers(headers, &server.config, server.vault().as_ref())
    })
    .map_err(|_| ())?;
    Ok(match auth.actor_class() {
        Some("human") => SigningCaller::Person,
        _ => SigningCaller::Agent,
    })
}

type NetworkPeer = Result<
    axum::extract::ConnectInfo<std::net::SocketAddr>,
    axum::extract::rejection::ExtensionRejection,
>;
type LocalPeer = Result<
    axum::extract::ConnectInfo<crate::managed::UnixPeer>,
    axum::extract::rejection::ExtensionRejection,
>;

fn signing_peer_ip(network: NetworkPeer, local: LocalPeer) -> Result<Option<String>, ()> {
    if let Ok(axum::extract::ConnectInfo(peer)) = network {
        return Ok(Some(peer.ip().to_string()));
    }
    if let Ok(axum::extract::ConnectInfo(peer)) = local
        && peer.verified()
    {
        // A kernel-verified Unix peer is the local supervisor, not a signer
        // address. Record no IP rather than inventing one or trusting XFF.
        return Ok(None);
    }
    Err(())
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

async fn pdf(
    State(server): State<Arc<SyncServer>>,
    SigningIngress { token, admitted }: SigningIngress,
    headers: HeaderMap,
    peer: NetworkPeer,
    local_peer: LocalPeer,
    body: Body,
) -> Response {
    let Ok(ip) = signing_peer_ip(peer, local_peer) else {
        return unavailable();
    };
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let request: ingress::ItemBody = match ingress::payload(&server, admitted, &headers, body).await
    {
        Ok(request) => request,
        Err(response) => return response,
    };
    match server
        .vault
        .esign_pdf_for_capability(&token, request.item, ip, ua)
    {
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
/// The signature image is the body itself, raw PNG or JPEG bytes: spooled
/// whole, then decoded and stored on the same worker. Only its capability and
/// turn, its format and visible pixels, and the decoder's bounds refuse it.
async fn image(
    State(server): State<Arc<SyncServer>>,
    SigningIngress { token, admitted }: SigningIngress,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let vault = Arc::clone(&server.vault);
    let uploaded = ingress::spooled(&server, admitted, &headers, body, move |file, bytes| {
        let image = ingress::whole_body(file, bytes)?;
        vault.upload_esign_signature_image(&token, &image).ok()
    })
    .await;
    match uploaded {
        Ok(Some(image_ref)) => (
            [
                (header::CACHE_CONTROL, "no-store"),
                (header::REFERRER_POLICY, "no-referrer"),
            ],
            Json(EsignSigningImageView { image_ref }),
        )
            .into_response(),
        Ok(None) => refused(),
        Err(response) => response,
    }
}
async fn path_token_refused() -> Response {
    (StatusCode::NOT_FOUND, "").into_response()
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
        let app = public_routes().with_state(server);
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
        let app = public_routes().with_state(server);
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
        let app = editor_routes().with_state(server);
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
