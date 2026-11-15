#![cfg(oneiron_test_support)]
//! DIRECT-ANSWER-PROOF-STORE-ERROR: a store fault met while binding a direct
//! request's proof fails the call, never refuses it as unauthenticated. The
//! owner's PERSON row is truncated past every write door, so the proof
//! builders' owner reads fail with a store error while request
//! authentication, which reads only authority rows, still verifies.
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --test direct_answer_proof_store_error`.

#[path = "support/engine_stack.rs"]
mod engine_stack;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{CapabilitySlip, holder_proof_challenge};
use oneiron::test_doors::owner_person_row_damage::truncate_embedded_owner_person_row;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

/// One vault, its server and the owner's own full human slip, which binds
/// owner authorship on a healthy vault.
struct OwnerClient {
    app: Router,
    vault: Arc<Vault>,
    owner: EntityId,
    slip: CapabilitySlip,
    key: SigningKey,
    token: String,
    _dir: tempfile::TempDir,
}

impl OwnerClient {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("fresh vault dir");
        let vault = Arc::new(
            Vault::open(dir.path(), VaultConfig::device()).expect("open fresh vault"),
        );
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        let server = Arc::new(
            SyncServer::new(
                Arc::clone(&vault),
                SyncServerConfig {
                    auth_secret: Some("direct-answer-proof-store-error".into()),
                    ..Default::default()
                },
            )
            .expect("create owner server"),
        );
        let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
        let root = vault.ensure_host_root_slip(&issuer).expect("host root slip");
        let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
        // The owner's own full slip: the root's claims, re-held by the
        // owner as a human, as the request fixtures mint one.
        let key = SigningKey::from_bytes(&[0x31; 32]);
        let mut claims = root.claims;
        claims.slip_id = [0x32; 32];
        claims.parent_id = None;
        claims.holder_ref = owner.to_hex();
        claims.binding_key = key.verifying_key().to_bytes();
        claims.actor_class = Some("human".to_owned());
        let slip = vault
            .mint_capability_slip(&issuer, claims)
            .expect("owner slip");
        let token = slip.to_token().expect("slip token");
        Self {
            app: build_app(server),
            vault,
            owner,
            slip,
            key,
            token,
            _dir: dir,
        }
    }

    async fn post(&self, path: &str, input: Value) -> (StatusCode, Value) {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let signature = hex(
            &self
                .key
                .sign(
                    &self
                        .slip
                        .binding_transcript(&challenge)
                        .expect("binding transcript"),
                )
                .to_bytes(),
        );
        let request = Request::post(path)
            .header("authorization", format!("Bearer {}", self.token))
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn world_body(vault: &Vault) -> Value {
    let name = "probe-world";
    json!({
        "kind": "WORLD",
        "body": {"name": name, "kind": "fictional"},
        "occurred_at": vault.now_recorded_at(),
        "text_fields": [{"field": "name", "value": name}]
    })
}

fn error_code(body: &Value) -> Option<&str> {
    body.pointer("/error/code").and_then(Value::as_str)
}

#[test]
fn direct_owner_authorship_store_fault_is_internal() {
    run_on_engine_stack(
        "direct-answer-proof-store-error",
        direct_owner_authorship_store_fault_is_internal_async,
    );
}

async fn direct_owner_authorship_store_fault_is_internal_async() {
    let client = OwnerClient::new();
    let (status, body) = client
        .post(
            "/v1/core/facade/vault.structural.put",
            world_body(&client.vault),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "healthy control: {body}");
    let damaged =
        truncate_embedded_owner_person_row(&client.vault).expect("truncate owner row");
    assert_eq!(damaged, client.owner);
    let (status, body) = client
        .post(
            "/v1/core/facade/vault.structural.put",
            world_body(&client.vault),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "a store fault binding owner authorship must fail the call, not refuse it: {body}"
    );
    assert_eq!(
        error_code(&body),
        Some("INTERNAL_SERVER_ERROR"),
        "{body}"
    );
}

#[test]
fn shared_person_proof_store_fault_is_internal() {
    run_on_engine_stack(
        "direct-answer-proof-store-error",
        shared_person_proof_store_fault_is_internal_async,
    );
}

async fn shared_person_proof_store_fault_is_internal_async() {
    let client = OwnerClient::new();
    let damaged =
        truncate_embedded_owner_person_row(&client.vault).expect("truncate owner row");
    assert_eq!(damaged, client.owner);
    let (status, body) = client
        .post(
            "/v1/core/facade/vault.shared.outcomes",
            json!({"vault_id": "1"}),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "a store fault binding a person's proof must fail the call, not refuse it: {body}"
    );
    assert_eq!(error_code(&body), Some("INTERNAL_SERVER_ERROR"), "{body}");
}

#[test]
fn direct_person_proof_store_fault_is_internal() {
    run_on_engine_stack(
        "direct-answer-proof-store-error",
        direct_person_proof_store_fault_is_internal_async,
    );
}

async fn direct_person_proof_store_fault_is_internal_async() {
    let client = OwnerClient::new();
    let damaged =
        truncate_embedded_owner_person_row(&client.vault).expect("truncate owner row");
    assert_eq!(damaged, client.owner);
    let (status, body) = client
        .post(
            "/v1/core/facade/vault.workspace.work_companion.set",
            json!({"workspace_ref": "probe", "policy": "choose"}),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "a store fault binding the person's proof must fail the call, not refuse it: {body}"
    );
    assert_eq!(
        error_code(&body),
        Some("INTERNAL_SERVER_ERROR"),
        "{body}"
    );
}
