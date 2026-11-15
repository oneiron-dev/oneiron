//! Live-run guard refusals keep their status through the real facade router.
#[path = "support/engine_stack.rs"]
mod engine_stack;

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use engine_stack::run_on_engine_stack;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

/// The facade's generated dispatch polls a frame of several MiB in a dev build
/// (`ENGINE_THREAD_STACK_BYTES`), more than a test thread's default stack, so
/// the router runs on threads sized as the server sizes its own.
#[test]
fn tasks_refuse_preserves_live_run_refusal_status_and_code() {
    run_on_engine_stack("facade-live-run-status", refuse_with_live_run_handles);
}

async fn refuse_with_live_run_handles() {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("facade-live-run-status-owner".into()),
                ..Default::default()
            },
        )
        .expect("create server"),
    );
    let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
    let slip = vault
        .ensure_host_root_slip(&issuer)
        .expect("owner root slip");
    let token = slip.to_token().expect("owner slip token");
    let app = build_app(server);

    // No run is registered in this fresh server. The first handle has the
    // guard's lr1.<32-hex run>.<32-hex issued> syntax, not a JSON decoding error.
    for (handle, expected_status, expected_code) in [
        (
            "lr1.11111111111111111111111111111111.22222222222222222222222222222222",
            StatusCode::FORBIDDEN,
            "live_run_unavailable",
        ),
        (
            "not-a-live-run-handle",
            StatusCode::BAD_REQUEST,
            "live_run_invalid",
        ),
    ] {
        // Each request proves possession afresh; the host secret is not a bearer.
        let timestamp = vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let signature: String = issuer
            .binding_proof(&slip, challenge.as_bytes())
            .expect("owner holder proof")
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let request = Request::post("/v1/core/facade/tasks.refuse")
            .header("authorization", format!("Bearer {token}"))
            .header(
                "x-oneiron-binding",
                json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string(),
            )
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "live_run": handle,
                    "spec": {
                        "domain": "bond",
                        "reasonRef": "cl_33333333333333333333333333333333"
                    }
                })
                .to_string(),
            ))
            .expect("tasks.refuse request");
        let response = app.clone().oneshot(request).await.expect("facade response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 16 * 1024)
            .await
            .expect("facade response body");
        let body: Value = serde_json::from_slice(&bytes).expect("facade error JSON");
        assert_eq!(
            (status, body["error"]["code"].as_str()),
            (expected_status, Some(expected_code)),
            "handle {handle}: {body}"
        );
    }
}
