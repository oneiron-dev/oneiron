//! FIX OWNER-ROUTE-CONFIRM-REFUSAL-CODE: on `/v1/owner`, the legal-hold
//! lift-and-erase confirm refused for a missing or stale shared confirm
//! answers 428 under the engine's own code `OWNER_CONFIRM_REQUIRED`, as the
//! facade does, so an owner-route client tells a confirm refusal from any
//! other by its code. The owner plane answered it as a generic refusal: a 409
//! `INVALID_STATE` carrying only the message.
//!
//! `cargo test --locked -p oneiron-server --all-features --test owner_lift_confirm_required`.

#![cfg(unix)]

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
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

const LIFT_AND_ERASE: &str = "/v1/owner/legal-holds/lift-and-erase";

/// The engine's code for a one-way act's missing or stale confirm.
const OWNER_CONFIRM_REQUIRED: &str = "OWNER_CONFIRM_REQUIRED";

/// A fresh self-hosted vault's owner, signing as the host root slip (as in
/// `federation_connect_host_fault_status.rs`).
struct OwnerClient {
    app: Router,
    vault: Arc<Vault>,
    issuer: HostSlipIssuer,
    slip: CapabilitySlip,
    token: String,
    _directory: tempfile::TempDir,
}

impl OwnerClient {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("a fresh vault directory");
        let vault = Arc::new(
            Vault::open(directory.path(), VaultConfig::device()).expect("open fresh vault"),
        );
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        let server = Arc::new(
            SyncServer::new(
                Arc::clone(&vault),
                SyncServerConfig {
                    auth_secret: Some("owner-lift-confirm-required".into()),
                    ..Default::default()
                },
            )
            .expect("create owner server"),
        );
        let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
        let slip = vault
            .ensure_host_root_slip(&issuer)
            .expect("owner root slip");
        let token = slip.to_token().expect("owner slip token");
        Self {
            app: build_app(server),
            vault,
            issuer,
            slip,
            token,
            _directory: directory,
        }
    }

    async fn post(&self, path: &str, input: Value) -> (StatusCode, Value) {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let signature: String = self
            .issuer
            .binding_proof(&self.slip, challenge.as_bytes())
            .expect("fresh owner holder proof")
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let token = &self.token;
        let request = Request::post(path)
            .header("authorization", format!("Bearer {token}"))
            .header(
                "x-oneiron-binding",
                json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string(),
            )
            .header("content-type", "application/json")
            .body(Body::from(input.to_string()))
            .expect("owner JSON request");
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("owner response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("owner response body");
        let body = serde_json::from_slice(&bytes).expect("owner response JSON");
        (status, body)
    }
}

/// A lift-and-erase confirm refused for its confirm answers 428 under the
/// engine's code, with the engine's way out.
fn assert_confirm_required(status: StatusCode, body: &Value, why: &str) {
    assert_eq!(status, StatusCode::PRECONDITION_REQUIRED, "{why}: {body}");
    assert_eq!(
        body["error"]["code"], OWNER_CONFIRM_REQUIRED,
        "{why}: {body}"
    );
    assert!(
        body["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("confirm")),
        "{why}: the engine's words: {body}"
    );
}

#[test]
fn a_lift_with_no_confirm_answers_428_under_its_code() {
    run_on_engine_stack("owner-lift-no-confirm", lift_with_no_confirm);
}

async fn lift_with_no_confirm() {
    let owner = OwnerClient::new();
    let (status, body) = owner
        .post(
            LIFT_AND_ERASE,
            json!({"records": [EntityId::now().to_hex()]}),
        )
        .await;
    assert_confirm_required(status, &body, "a lift that carries no confirm");
}

#[test]
fn a_lift_with_a_stale_confirm_answers_428_under_its_code() {
    run_on_engine_stack("owner-lift-stale-confirm", lift_with_stale_confirm);
}

async fn lift_with_stale_confirm() {
    let owner = OwnerClient::new();
    let (status, body) = owner
        .post(
            LIFT_AND_ERASE,
            json!({"records": [EntityId::now().to_hex()], "confirm": "00".repeat(32)}),
        )
        .await;
    assert_confirm_required(
        status,
        &body,
        "a lift whose confirm is no live preview of it",
    );
}

#[test]
fn a_malformed_lift_still_answers_400() {
    run_on_engine_stack("owner-lift-malformed", malformed_lift);
}

async fn malformed_lift() {
    let owner = OwnerClient::new();
    let (status, body) = owner
        .post(
            LIFT_AND_ERASE,
            json!({"records": [EntityId::now().to_hex()], "check_in_ref": "not-hex"}),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a malformed check-in ref: {body}"
    );
    assert_eq!(body["error"]["code"], "BAD_REQUEST", "{body}");
}
