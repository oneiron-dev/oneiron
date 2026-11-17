//! [API-FLOOR-CHUNKED-413-UNTYPED] (FIX-LIST line 25846): a request body
//! past `limits.request_body_bytes` is refused with the typed
//! `PAYLOAD_TOO_LARGE` envelope naming the row, whether it declared its
//! length or arrived chunked. On main only a declared length was named: a
//! chunked oversize body kept axum's plain-text 413.
//!
//! Each case drives the real route `POST /v1/usage/events` in process
//! (`build_app(..).oneshot(..)`, no TCP ports, no sleeps, no credentials:
//! `allow_unauthenticated`, as `src/api/tests/billing_usage.rs` serves it).
//! The route reads its body through axum's bare `Json` extractor under no
//! bound of its own, so the floor is the bound that refuses. The floor is
//! 2048 bytes here; the oversize bodies are 4096.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --test api_floor_chunked_413_untyped`.
#![cfg(oneiron_test_support)]

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, Bytes, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use futures_util::stream;
use oneiron::{Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::runtime::{
    RuntimeConfig, RuntimeConfigOverride, RuntimeMode, RuntimeRole, RuntimeRoleTargetOverride,
};
use oneiron_server::{
    ENGINE_THREAD_STACK_BYTES, build_app, config::SyncServerConfig, server::SyncServer,
};
use serde_json::{Value, json};
use tower::ServiceExt;

/// The request floor this test serves under.
const FLOOR: u64 = 2_048;
/// An oversize body: twice the floor.
const OVERSIZE: usize = 4_096;
/// The route under test: bare `Json`, no bound of its own, not keyed.
const EVENTS: &str = "/v1/usage/events";

/// Runs `test` on an engine-sized stack and runtime, as the served doors
/// need more than a test thread's default stack.
fn run_on_engine_stack(name: &str, test: impl std::future::Future<Output = ()> + Send + 'static) {
    let run = std::thread::Builder::new()
        .name(name.into())
        .stack_size(ENGINE_THREAD_STACK_BYTES)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(ENGINE_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .expect("engine-sized test runtime")
                .block_on(test)
        })
        .expect("spawn the engine-sized test thread");
    if let Err(panic) = run.join() {
        std::panic::resume_unwind(panic);
    }
}

struct Host {
    _dir: tempfile::TempDir,
    app: Router,
}

/// A served vault with the request floor at [`FLOOR`] and the runtime's
/// hosted orchestrator route, so the under-limit control records (the
/// `billing_usage.rs` hosted-route fixture).
fn host() -> Host {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let mut vault_config = VaultConfig::device();
    vault_config.map_size = 64 * 1024 * 1024;
    vault_config.dimensions = 4;
    vault_config.embedding_model = None;
    let vault = Arc::new(Vault::open(dir.path(), vault_config).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let mut runtime = RuntimeConfig::for_mode(RuntimeMode::LocalFree);
    runtime.apply_override(RuntimeConfigOverride::with_role_override(
        RuntimeRole::Orchestrator,
        RuntimeRoleTargetOverride {
            mode: Some(RuntimeMode::OneironCloud),
            provider_kind: None,
            model: Some("hosted-orchestrator".to_owned()),
        },
    ));
    let mut server_config = SyncServerConfig {
        allow_unauthenticated: true,
        runtime,
        ..Default::default()
    };
    server_config.limits.request_body_bytes = FLOOR;
    let server = Arc::new(SyncServer::new(vault, server_config).expect("create server"));
    let app = build_app(server);
    Host { _dir: dir, app }
}

/// Valid JSON of exactly `size` bytes: `{"pad":"..."}`. The floor refuses
/// it before any parse, but valid JSON keeps the refusal about the size.
fn oversized_json(size: usize) -> Vec<u8> {
    let pad = "p".repeat(size - 10);
    let body = format!("{{\"pad\":\"{pad}\"}}").into_bytes();
    assert_eq!(body.len(), size);
    body
}

/// `bytes` as a chunked body arrives: streamed in two pieces, with no
/// `Content-Length` for the floor to read.
fn chunked(bytes: Vec<u8>) -> Body {
    let mid = bytes.len() / 2;
    let mut head = bytes;
    let tail = head.split_off(mid);
    Body::from_stream(stream::iter([
        Ok::<Bytes, std::io::Error>(Bytes::from(head)),
        Ok(Bytes::from(tail)),
    ]))
}

/// POSTs `body` to the route; `content_length` is sent as the
/// `Content-Length` header, or no header when `None` (chunked).
async fn post(app: &Router, body: Body, content_length: Option<usize>) -> (StatusCode, Bytes) {
    let mut request = Request::post(EVENTS).header("content-type", "application/json");
    if let Some(length) = content_length {
        request = request.header("content-length", length.to_string());
    }
    let mut request = request.body(body).expect("request");
    // The hatch serves only this device's callers: the request comes from
    // loopback, as a local client's does.
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));
    let response = app.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let raw = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    (status, raw)
}

/// The typed floor refusal: `PAYLOAD_TOO_LARGE` naming the row, the bound
/// and the bytes received.
fn assert_floor_envelope(raw: &[u8], received_bytes: u64) {
    let answer: Value = serde_json::from_slice(raw).unwrap_or_else(|_| {
        panic!(
            "the floor refusal is no typed envelope: {}",
            String::from_utf8_lossy(raw)
        )
    });
    assert_eq!(answer["code"], Value::from("PAYLOAD_TOO_LARGE"), "{answer}");
    assert_eq!(
        answer["details"]["code"],
        Value::from("PAYLOAD_TOO_LARGE"),
        "{answer}"
    );
    assert_eq!(answer["details"]["field"], Value::from("body"), "{answer}");
    let message = answer["message"].as_str().unwrap_or_default();
    assert!(message.contains("limits.request_body_bytes"), "{answer}");
    assert_eq!(
        answer["details"]["maxBytes"],
        Value::from(FLOOR),
        "{answer}"
    );
    assert_eq!(
        answer["details"]["receivedBytes"],
        Value::from(received_bytes),
        "{answer}"
    );
}

/// The control that records: the `billing_usage.rs` hosted-route event.
fn control_event() -> Value {
    json!({
        "owner": "owner-a",
        "vaultId": "vault-a",
        "idempotencyKey": "floor-control",
        "source": "local",
        "eventType": "inference",
        "model": "hosted-orchestrator",
        "tokenCounts": {
            "inputTokens": 1000,
            "outputTokens": 500,
            "cacheReadTokens": 0,
            "cacheWriteTokens": 0
        },
        "costRates": { "currency": "USD", "priceTableSnapshot": "fixture",
            "inputPerMillion": 2000000000,
            "outputPerMillion": 4000000000_u64,
            "cacheReadPerMillion": 0,
            "cacheWritePerMillion": 0
        }
    })
}

#[test]
fn a_declared_body_past_the_floor_is_refused_typed() {
    run_on_engine_stack("floor-declared", async {
        let host = host();
        let body = oversized_json(OVERSIZE);
        assert!(body.len() > FLOOR as usize);
        let (status, raw) = post(&host.app, Body::from(body.clone()), Some(body.len())).await;
        assert_eq!(
            status,
            StatusCode::PAYLOAD_TOO_LARGE,
            "declared oversize: {}",
            String::from_utf8_lossy(&raw)
        );
        assert_floor_envelope(&raw, body.len() as u64);
    });
}

#[test]
fn a_chunked_body_past_the_floor_is_refused_typed() {
    run_on_engine_stack("floor-chunked", async {
        let host = host();
        let body = oversized_json(OVERSIZE);
        assert!(body.len() > FLOOR as usize);
        // The floor stops reading at the first piece that passes it: the
        // first half when it alone does, else both halves.
        let half = (body.len() / 2) as u64;
        let arrived = if half > FLOOR {
            half
        } else {
            body.len() as u64
        };
        let (status, raw) = post(&host.app, chunked(body), None).await;
        assert_eq!(
            status,
            StatusCode::PAYLOAD_TOO_LARGE,
            "chunked oversize: {}",
            String::from_utf8_lossy(&raw)
        );
        // Undeclared: the bytes that arrived before the floor refused.
        assert_floor_envelope(&raw, arrived);
    });
}

#[test]
fn a_body_under_the_floor_passes() {
    run_on_engine_stack("floor-under", async {
        let host = host();
        let body = serde_json::to_string(&control_event()).expect("control JSON");
        assert!(body.len() < FLOOR as usize, "control is {body}");
        let (status, raw) = post(&host.app, Body::from(body), None).await;
        let answer: Value = serde_json::from_slice(&raw).unwrap_or_else(|_| {
            panic!(
                "the control answered no JSON: {}",
                String::from_utf8_lossy(&raw)
            )
        });
        assert_eq!(status, StatusCode::OK, "{answer}");
        assert_eq!(answer["recorded"], Value::from(true), "{answer}");
    });
}
