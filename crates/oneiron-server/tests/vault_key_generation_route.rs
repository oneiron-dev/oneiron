//! The owner's surfaces for a new data-key generation: the preview names
//! every wrap the act would remove, the act refuses a way neither presented
//! nor confirmed and changes nothing, it rewraps the presented ways and
//! removes the confirmed ones, and a wrong password refuses it.
//!
//! Each case drives the real routes in process (`build_app` + `oneshot`, no
//! TCP, no sleeps) with the owner's host-root credential: it sets the vault
//! up through the routes themselves (a device wrap, a password, one passkey),
//! reads wrap ids back from `GET /v1/owner/vault-key`, and, after the act,
//! locks and unlocks with the password, which checks the opened key against
//! the stored commitment and so proves the password wrap is of the new key.
//!
//! Red at the base: the generation routes do not exist (404), so every case
//! fails at its first generation call. Green at the head.
//!
//! Deterministic: in-process vault and router, `MemoryKeystore`, no models.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! --locked -p oneiron-server --all-features --features oneiron/test-support
//! --test vault_key_generation_route`.

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

const PASSWORD: &str = "correct horse battery staple";
const PASSKEY: &str = "old-key";
const STATUS: &str = "/v1/owner/vault-key";
const DEVICE: &str = "/v1/owner/vault-key/device";
const SET_PASSWORD: &str = "/v1/owner/vault-key/password";
const PASSKEYS: &str = "/v1/owner/vault-key/passkeys";
const PREVIEW: &str = "/v1/owner/vault-key/generation/preview";
const GENERATE: &str = "/v1/owner/vault-key/generation";
const LOCK: &str = "/v1/owner/vault-key/lock";
const UNLOCK: &str = "/v1/owner/vault-key/unlock";

/// A served vault with the owner's credential, before any wrap.
struct Host {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl Host {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("temporary vault directory");
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
        vault.install_device_keystore(Arc::new(MemoryKeystore::default()));
        let server = Arc::new(
            SyncServer::new(
                Arc::clone(&vault),
                SyncServerConfig {
                    auth_secret: Some("vault-key-generation-route".into()),
                    ..Default::default()
                },
            )
            .expect("create server"),
        );
        let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
        let owner_slip = vault
            .ensure_host_root_slip(&issuer)
            .expect("owner root slip");
        let owner_token = owner_slip.to_token().expect("owner slip token");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's live machine profile");
        let app = build_app(server);
        Self {
            _dir: dir,
            vault,
            app,
            issuer,
            owner_slip,
            owner_token,
        }
    }

    fn owner_binding(&self) -> String {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let signature: String = hex(&self
            .issuer
            .binding_proof(&self.owner_slip, challenge.as_bytes())
            .expect("owner holder proof"));
        json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
    }

    /// The owner's call: its status and its answer, the answer as text when
    /// it is not JSON.
    async fn call(&self, method: &str, path: &str, body: Option<Value>) -> (StatusCode, Value) {
        let builder = Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", format!("Bearer {}", self.owner_token))
            .header("x-oneiron-binding", self.owner_binding());
        let builder = match &body {
            Some(_) => builder.header("content-type", "application/json"),
            None => builder,
        };
        let request = builder
            .body(Body::from(
                body.map(|body| body.to_string()).unwrap_or_default(),
            ))
            .expect("owner request");
        let response = self.app.clone().oneshot(request).await.expect("response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("response body");
        let answer = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        (status, answer)
    }

    async fn post(&self, path: &str, body: Option<Value>) -> (StatusCode, Value) {
        self.call("POST", path, body).await
    }

    async fn get(&self, path: &str) -> (StatusCode, Value) {
        self.call("GET", path, None).await
    }

    /// The vault's wraps through the routes: a device wrap, the password,
    /// and one passkey.
    async fn setup_ways(&self) {
        let (status, answer) = self.post(DEVICE, None).await;
        assert_eq!(status, StatusCode::OK, "the device wrap: {answer}");
        let (status, answer) = self
            .post(SET_PASSWORD, Some(json!({"password": PASSWORD})))
            .await;
        assert_eq!(status, StatusCode::OK, "the password wrap: {answer}");
        let prf = "05".repeat(32);
        let (status, answer) = self
            .post(PASSKEYS, Some(json!({"credential": PASSKEY, "prf": prf})))
            .await;
        assert_eq!(status, StatusCode::OK, "the passkey wrap: {answer}");
    }

    /// Every wrap id `GET /v1/owner/vault-key` names, sorted.
    async fn wrap_ids(&self) -> Vec<String> {
        let (status, answer) = self.get(STATUS).await;
        assert_eq!(status, StatusCode::OK, "the vault-key status: {answer}");
        wrap_ids_in(&answer, "wraps")
    }

    /// This install's device wrap id.
    async fn device_id(&self) -> String {
        self.wrap_ids()
            .await
            .into_iter()
            .find(|id| id.starts_with("device:"))
            .expect("this install's device wrap")
    }
}

/// The ids under `answer[field][]`, sorted.
fn wrap_ids_in(answer: &Value, field: &str) -> Vec<String> {
    let mut ids: Vec<String> = answer[field]
        .as_array()
        .unwrap_or_else(|| panic!("{field} is a list: {answer}"))
        .iter()
        .map(|wrap| {
            wrap["id"]
                .as_str()
                .unwrap_or_else(|| panic!("a wrap has an id: {answer}"))
                .to_owned()
        })
        .collect();
    ids.sort();
    ids
}

#[test]
fn the_preview_names_every_way_the_owner_does_not_keep() {
    run_on_engine_stack("vault-key-generation-preview", || async {
        let host = Host::new();
        host.setup_ways().await;
        let device = host.device_id().await;
        let (status, answer) = host.post(PREVIEW, Some(json!({"password": true}))).await;
        assert_eq!(status, StatusCode::OK, "the preview lands: {answer}");
        let removes = wrap_ids_in(&answer, "removes");
        assert_eq!(removes, [format!("passkey:{PASSKEY}")]);
        assert!(
            !removes.contains(&device),
            "the device wrap is never named: {answer}"
        );
        let (status, answer) = host.post(PREVIEW, Some(json!({}))).await;
        assert_eq!(status, StatusCode::OK, "the empty preview lands: {answer}");
        let removes = wrap_ids_in(&answer, "removes");
        assert_eq!(
            removes,
            [format!("passkey:{PASSKEY}"), "password".to_owned()]
        );
        assert!(
            !removes.contains(&device),
            "the device wrap is never named: {answer}"
        );
    });
}

#[test]
fn the_act_refuses_a_way_neither_presented_nor_confirmed_and_changes_nothing() {
    run_on_engine_stack("vault-key-generation-unconfirmed", || async {
        let host = Host::new();
        host.setup_ways().await;
        let before = host.wrap_ids().await;
        let (status, answer) = host
            .post(GENERATE, Some(json!({"password": PASSWORD})))
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{answer}");
        assert!(
            answer.to_string().contains(&format!("passkey:{PASSKEY}")),
            "the refusal names the way: {answer}"
        );
        assert_eq!(host.wrap_ids().await, before, "nothing changed");
    });
}

#[test]
fn the_act_rewraps_the_presented_ways_and_removes_the_confirmed_ones() {
    run_on_engine_stack("vault-key-generation-act", || async {
        let host = Host::new();
        host.setup_ways().await;
        let device = host.device_id().await;
        let (status, answer) = host
            .post(
                GENERATE,
                Some(json!({
                    "password": PASSWORD,
                    "confirmed_removals": [format!("passkey:{PASSKEY}")],
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "the act lands: {answer}");
        assert_eq!(answer["generation"].as_u64(), Some(1), "{answer}");
        assert_eq!(
            wrap_ids_in(&answer, "removed"),
            [format!("passkey:{PASSKEY}")],
            "{answer}"
        );
        let rewrapped = wrap_ids_in(&answer, "rewrapped");
        assert!(
            rewrapped.contains(&"password".to_owned()) && rewrapped.contains(&device),
            "the password and this install's device wrap are rewrapped: {answer}"
        );
        let ids = host.wrap_ids().await;
        assert!(
            ids.iter().all(|id| !id.starts_with("passkey:")),
            "no passkey wrap stands: {ids:?}"
        );
        let (status, answer) = host.post(LOCK, None).await;
        assert_eq!(status, StatusCode::OK, "the lock lands: {answer}");
        let (status, answer) = host
            .post(
                UNLOCK,
                Some(json!({"method": "password", "password": PASSWORD})),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the password opens the new key: {answer}"
        );
    });
}

#[test]
fn a_wrong_password_refuses_the_act() {
    run_on_engine_stack("vault-key-generation-wrong-password", || async {
        let host = Host::new();
        host.setup_ways().await;
        let before = host.wrap_ids().await;
        let (status, answer) = host
            .post(
                GENERATE,
                Some(json!({
                    "password": "not the password",
                    "confirmed_removals": [format!("passkey:{PASSKEY}")],
                })),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{answer}");
        assert!(
            answer.to_string().contains("does not open its wrap"),
            "the refusal names the unopened wrap: {answer}"
        );
        assert_eq!(host.wrap_ids().await, before, "nothing changed");
    });
}
