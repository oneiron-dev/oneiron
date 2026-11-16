//! `GET /v1/owner/embedding-spaces` lists the declared spaces, not the
//! conflict queue: its OpenAPI summary must say so. The route carried the
//! contradiction-list summary by a copy-paste (FIX-LIST L4159).

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::{Extension, Router};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::Value;
use tower::ServiceExt;

fn app() -> (tempfile::TempDir, Router) {
    let dir = tempfile::tempdir().expect("vault dir");
    let vault = Arc::new(
        oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).expect("open vault"),
    );
    let server = Arc::new(
        SyncServer::new(
            vault,
            SyncServerConfig {
                allow_unauthenticated: true,
                ..Default::default()
            },
        )
        .expect("sync server"),
    );
    // A hatch server answers only callers on this device: each request
    // comes from a loopback peer.
    let loopback = ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0)));
    (dir, build_app(server).layer(Extension(loopback)))
}

async fn served_spec(app: &Router) -> Value {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/openapi.json")
                .body(Body::empty())
                .expect("OpenAPI request"),
        )
        .await
        .expect("serve OpenAPI");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("OpenAPI body");
    serde_json::from_slice(&body).expect("OpenAPI JSON")
}

#[tokio::test]
async fn embedding_spaces_list_summary_names_spaces_not_contradictions() {
    let (_dir, app) = app();
    let spec = served_spec(&app).await;
    let summary = spec["paths"]["/v1/owner/embedding-spaces"]["get"]["summary"]
        .as_str()
        .expect("GET /v1/owner/embedding-spaces is in the OpenAPI document with a summary");
    assert_eq!(
        summary, "Every space, slot, move and probe count.",
        "GET /v1/owner/embedding-spaces carries the contradiction-list summary"
    );
}

#[tokio::test]
async fn conflicts_list_summary_still_names_contradictions() {
    let (_dir, app) = app();
    let spec = served_spec(&app).await;
    let summary = spec["paths"]["/v1/owner/conflicts"]["get"]["summary"]
        .as_str()
        .expect("GET /v1/owner/conflicts is in the OpenAPI document with a summary");
    assert_eq!(
        summary, "Every unanswered contradiction, oldest first.",
        "the conflicts summary moved; it is the text the embedding-spaces route copied"
    );
}
