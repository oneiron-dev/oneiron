//! The participants' off-record room routes (`/v1/core/off-record`) are in the
//! served OpenAPI document, with their rows' request and answer shapes, and
//! every room route the document names is served.

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode, header};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::Value;
use tower::ServiceExt;

/// Every route `api::off_record_rooms::routes` serves under `/v1/core/off-record`.
const ROOM_ROUTES: &[(&str, &str)] = &[
    ("get", "/v1/core/off-record"),
    ("post", "/v1/core/off-record/start"),
    ("post", "/v1/core/off-record/witness"),
    ("post", "/v1/core/off-record/save"),
    ("post", "/v1/core/off-record/export"),
    ("post", "/v1/core/off-record/save-from-here"),
    ("post", "/v1/core/off-record/suggest-save"),
    ("post", "/v1/core/off-record/confirm-save"),
    ("post", "/v1/core/off-record/decline-save"),
];

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
async fn openapi_documents_every_off_record_room_route() {
    let (_dir, app) = app();
    let spec = served_spec(&app).await;
    for &(method, path) in ROOM_ROUTES {
        let operation = &spec["paths"][path][method];
        assert!(
            operation.is_object(),
            "{method} {path} is served but not in the OpenAPI document"
        );
        if method == "get" {
            let names: Vec<&str> = operation["parameters"]
                .as_array()
                .expect("query parameters")
                .iter()
                .filter_map(|parameter| parameter["name"].as_str())
                .collect();
            assert!(
                names.contains(&"room") && names.contains(&"session_ref"),
                "{path} names its stretch in the query: {names:?}"
            );
        } else {
            assert!(
                operation["requestBody"]["content"]["application/json"]["schema"].is_object(),
                "{path} documents its request body"
            );
        }
        let answer = &operation["responses"]["200"];
        assert!(
            answer["content"]["application/json"]["schema"].is_object(),
            "{path} documents its answer"
        );
        assert_eq!(
            answer["headers"]["x-oneiron-receipt-ref"]["schema"]["const"], "none; no-record",
            "{path} keeps no call receipt"
        );
    }
    assert_eq!(
        spec["paths"]["/v1/core/off-record/export"]["post"]["responses"]["200"]["headers"]["Content-Disposition"]
            ["schema"]["const"],
        "attachment; filename=\"off-record-talk.json\"",
        "the export answers an attachment"
    );
}

#[tokio::test]
async fn every_documented_off_record_room_route_is_served() {
    let (_dir, app) = app();
    let spec = served_spec(&app).await;
    let paths = spec["paths"].as_object().expect("paths");
    let mut documented = 0;
    for (path, item) in paths {
        if !path.starts_with("/v1/core/off-record") {
            continue;
        }
        for method in item.as_object().expect("path item").keys() {
            documented += 1;
            let request = Request::builder()
                .method(Method::from_bytes(method.to_uppercase().as_bytes()).expect("method"))
                .uri(path.as_str())
                .header(header::CONTENT_TYPE, "application/json")
                .body(if method == "get" {
                    Body::empty()
                } else {
                    Body::from("{}")
                })
                .expect("route request");
            let status = app.clone().oneshot(request).await.expect("route").status();
            assert!(
                status != StatusCode::NOT_FOUND && status != StatusCode::METHOD_NOT_ALLOWED,
                "{method} {path} is documented but not served: {status}"
            );
        }
    }
    assert_eq!(documented, ROOM_ROUTES.len());
}
