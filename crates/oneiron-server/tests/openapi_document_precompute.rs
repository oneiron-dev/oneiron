//! `serve` assembles the OpenAPI document on a thread of its own at start, so
//! the first `GET /api/openapi.json` after it assembles nothing
//! (FIX [SLOW-FACADE-CALLS-COORDINATION-08]). One test per binary: it needs a
//! process that has not assembled the document yet.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test -p oneiron-server --test openapi_document_precompute`
#![cfg(oneiron_test_support)]

use std::sync::Arc;
use std::time::Instant;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use oneiron_server::test_doors::openapi_document::{assemblies, spawn_precompute};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::Value;
use tower::ServiceExt;

#[tokio::test]
async fn first_openapi_request_after_the_precompute_assembles_nothing() {
    assert_eq!(
        assemblies(),
        0,
        "this process assembled the document before the precompute"
    );
    let started = Instant::now();
    spawn_precompute()
        .expect("spawn the precompute thread")
        .join()
        .expect("the precompute thread ends");
    let precompute_ms = started.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(
        assemblies(),
        1,
        "the precompute assembled the document once"
    );

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
    let started = Instant::now();
    let response = build_app(server)
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
    let request_ms = started.elapsed().as_secs_f64() * 1000.0;
    println!(
        "## OPENAPI precompute_ms={precompute_ms:.1} first_request_ms={request_ms:.1} bytes={}",
        body.len()
    );
    assert_eq!(
        assemblies(),
        1,
        "the first request after the precompute assembled the document again"
    );
    let document: Value = serde_json::from_slice(&body).expect("OpenAPI JSON");
    assert!(
        document["paths"]["/api/openapi.json"]["get"].is_object(),
        "the served document names its own route"
    );
}
