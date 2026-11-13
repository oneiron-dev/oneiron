//! `GET /api/openapi.json` serves the document its process assembled once: a
//! second request reuses it and assembles nothing. Assembling it cost 2.05 s
//! per E2E case in the dev build, every request
//! (FIX [SLOW-FACADE-CALLS-COORDINATION-08]).
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test -p oneiron-server --test openapi_document_reuse`

use std::sync::Arc;
use std::time::Instant;

use axum::Router;
use axum::body::{Body, Bytes, to_bytes};
use axum::http::{Request, StatusCode, header};
use oneiron_server::test_doors::openapi_document::assemblies;
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
    (dir, build_app(server))
}

/// The served body and the request's wall time in milliseconds.
async fn served_document(app: &Router) -> (Bytes, f64) {
    let started = Instant::now();
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
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json"),
        "the document is served as JSON"
    );
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("OpenAPI body");
    (body, started.elapsed().as_secs_f64() * 1000.0)
}

#[tokio::test]
async fn second_openapi_request_reuses_the_assembled_document() {
    let (_dir, app) = app();
    let before = assemblies();
    let (first, first_ms) = served_document(&app).await;
    let after_first = assemblies();
    let (second, second_ms) = served_document(&app).await;
    let after_second = assemblies();
    println!(
        "## OPENAPI request=1 ms={first_ms:.1} assembled={} request=2 ms={second_ms:.1} assembled={} bytes={}",
        after_first - before,
        after_second - after_first,
        first.len()
    );
    assert!(
        after_first - before <= 1,
        "the first GET /api/openapi.json assembled the document {} times",
        after_first - before
    );
    assert_eq!(
        after_second - after_first,
        0,
        "the second GET /api/openapi.json assembled the document again ({first_ms:.0} ms, then {second_ms:.0} ms)"
    );
    assert_eq!(first, second, "two requests served different documents");
    let document: Value = serde_json::from_slice(&second).expect("OpenAPI JSON");
    assert!(
        document["paths"]["/api/openapi.json"]["get"].is_object(),
        "the served document names its own route"
    );
}
