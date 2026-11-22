//! [MESH-DOOR-REFUSAL-STATUS-500]: a mesh door the host cannot sign
//! for answers the refusal's own status, not a server fault. This server
//! holds no host issuer (no keystore, default config), so every mesh door
//! refuses through `with_issuer` with `ApiError::unauthorized`; the facade
//! answers that refusal as 401 `UNAUTHORIZED`, never 500. A malformed body
//! is still refused before the door, as 400.
//!
//! Run with: `cargo test --locked -p oneiron-server --all-features
//! --test mesh_door_refusal_status`.
#[path = "support/engine_stack.rs"]
mod engine_stack;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

/// The facade's generated dispatch polls a frame of several MiB in a dev build
/// (`ENGINE_THREAD_STACK_BYTES`), more than a test thread's default stack, so
/// the router runs on threads sized as the server sizes its own.
#[test]
fn an_owner_mesh_revoke_the_host_cannot_sign_answers_401() {
    run_on_engine_stack("mesh-door-refusal-status", mesh_revoke_answers_401);
}

#[test]
fn an_owner_mesh_alpn_grant_the_host_cannot_sign_answers_401() {
    run_on_engine_stack("mesh-door-refusal-status", mesh_alpn_grant_answers_401);
}

#[test]
fn a_malformed_mesh_revoke_body_still_answers_400() {
    run_on_engine_stack(
        "mesh-door-refusal-status",
        malformed_mesh_revoke_answers_400,
    );
}

/// One owner-signed facade call and its status, error code and body.
struct OwnerCaller {
    app: Router,
    vault: Arc<Vault>,
    issuer: HostSlipIssuer,
    slip: CapabilitySlip,
    token: String,
    _dir: tempfile::TempDir,
}

impl OwnerCaller {
    async fn call(&self, verb: &str, body: &Value) -> (StatusCode, Option<String>, Value) {
        // Each request proves possession afresh; the host secret is not a bearer.
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let signature: String = self
            .issuer
            .binding_proof(&self.slip, challenge.as_bytes())
            .expect("owner holder proof")
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let request = Request::post(format!("/v1/core/facade/{verb}"))
            .header("authorization", format!("Bearer {}", self.token))
            .header(
                "x-oneiron-binding",
                json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string(),
            )
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("facade request");
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("facade response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("facade response body");
        let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        let code = body["error"]["code"].as_str().map(str::to_owned);
        (status, code, body)
    }
}

/// A serving install whose host holds no issuer: no keystore and a default
/// config, so `with_issuer` refuses every mesh door with `unauthorized`.
/// HTTP trusts the logged issuer of each mint, so the owner's root slip
/// still proves the owner at the facade.
async fn owner_caller() -> OwnerCaller {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    let issuer =
        HostSlipIssuer::from_secret(b"oneiron-test-mesh-door-refusal-status").expect("host issuer");
    let slip = vault
        .ensure_host_root_slip(&issuer)
        .expect("owner root slip");
    let token = slip.to_token().expect("owner slip token");
    let server = Arc::new(
        SyncServer::new(vault.clone(), SyncServerConfig::default()).expect("create server"),
    );
    OwnerCaller {
        app: build_app(server),
        vault,
        issuer,
        slip,
        token,
        _dir: dir,
    }
}

async fn mesh_revoke_answers_401() {
    let caller = owner_caller().await;
    // A well-formed revoke for a machine the vault never paired: the door
    // refuses before any pairing is read, where the host cannot sign.
    let (status, code, body) = caller
        .call(
            "vault.mesh.revoke_machine",
            &json!({ "machine": EntityId::now().to_hex() }),
        )
        .await;
    assert_eq!(
        (status, code.as_deref()),
        (StatusCode::UNAUTHORIZED, Some("UNAUTHORIZED")),
        "a mesh revoke the host cannot sign: {body}"
    );
}

async fn mesh_alpn_grant_answers_401() {
    let caller = owner_caller().await;
    let (status, code, body) = caller
        .call(
            "vault.mesh.set_alpn_grant",
            &json!({
                "machine": EntityId::now().to_hex(),
                "endpoint_key": vec![0xA1u8; 32],
                "alpn": b"oneiron/sync/1".to_vec(),
                "allow": true,
            }),
        )
        .await;
    assert_eq!(
        (status, code.as_deref()),
        (StatusCode::UNAUTHORIZED, Some("UNAUTHORIZED")),
        "a mesh ALPN grant the host cannot sign: {body}"
    );
}

async fn malformed_mesh_revoke_answers_400() {
    let caller = owner_caller().await;
    // No machine: the facade refuses the body before the door is reached.
    let (status, code, body) = caller.call("vault.mesh.revoke_machine", &json!({})).await;
    assert_eq!(
        (status, code.as_deref()),
        (StatusCode::BAD_REQUEST, Some("BAD_REQUEST")),
        "a malformed mesh revoke body: {body}"
    );
}
