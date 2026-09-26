//! Hosted public signing links must not inherit tenant device-lease admission.
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use oneiron_server::build_app;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::server::SyncServer;
use std::sync::Arc;
use tower::ServiceExt;

#[tokio::test]
async fn hosted_signing_is_public_but_tenant_routes_still_require_a_lease() {
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
    let token = "ab".repeat(32);
    let page = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/sign/{token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    assert_eq!(page.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(page.headers()[header::REFERRER_POLICY], "no-referrer");
    assert!(page.headers().contains_key(header::CONTENT_SECURITY_POLICY));
    let bytes = to_bytes(page.into_body(), 16 * 1024).await.unwrap();
    let html = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(
        !html.contains(&token),
        "capability must not be in the HTML body"
    );
    let refusal = app
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
    assert_eq!(refusal.status(), StatusCode::FORBIDDEN);
    let invalid = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/sign/not-a-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::FORBIDDEN);
    let denied = app
        .oneshot(
            Request::builder()
                .uri("/api/entity/00112233445566778899aabbccddeeff")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
}
