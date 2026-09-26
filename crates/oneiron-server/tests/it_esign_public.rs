//! The public path and signing API are separate from hosted device leases.
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use std::sync::Arc;
use tower::ServiceExt;

#[tokio::test]
async fn public_path_signing_bypasses_hosted_lease_but_not_capability_admission() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    let server = Arc::new(
        SyncServer::new(
            vault,
            SyncServerConfig {
                lease_vault_id: 1,
                ..Default::default()
            },
        )
        .unwrap(),
    );
    let app = build_app(server);
    let token = "11".repeat(32);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/sign/{token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::REFERRER_POLICY], "no-referrer");
    assert!(
        response
            .headers()
            .contains_key(header::CONTENT_SECURITY_POLICY)
    );
    assert!(!response.headers().contains_key(header::LOCATION));
    assert!(!response.headers().contains_key(header::SET_COOKIE));
    let body = to_bytes(response.into_body(), 128 * 1024).await.unwrap();
    assert!(!String::from_utf8_lossy(&body).contains(&token));

    let malformed = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/sign/not-a-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(malformed.status(), StatusCode::NOT_FOUND);
    assert_eq!(malformed.headers()[header::CACHE_CONTROL], "no-store");
    let unavailable = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/sign/action")
                .extension(axum::extract::ConnectInfo(
                    "127.0.0.1:12345".parse::<std::net::SocketAddr>().unwrap(),
                ))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({"token":token,"action":{"action":"load"}}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unavailable.status(), StatusCode::FORBIDDEN);
    assert_eq!(unavailable.headers()[header::CACHE_CONTROL], "no-store");
    // Bypassing the device lease is scoped to the ceremony, not its
    // owner-side geometry editor or the rest of the hosted API.
    for path in ["/sign/editor", "/api/openapi.json"] {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
    }
}
