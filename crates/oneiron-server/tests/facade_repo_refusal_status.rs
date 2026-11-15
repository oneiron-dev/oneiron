//! A repo door's typed refusal keeps its own status through the real facade
//! router (NO-DOOR REPO-MEMBER-SNAPSHOT-SYMBOL-READ): a caller no Grant
//! admits to a repo is refused with 403 `repo_no_membership`, never a server
//! failure. `vault.repo.symbols.observe` (NO-DOOR SYMBOL-LEASE-OBSERVATION)
//! and `vault.repo.proposal_resolve` are routed run doors: an unknown live
//! run meets the live-run guard first.
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

/// The facade's generated dispatch polls a frame of several MiB in a dev build
/// (`ENGINE_THREAD_STACK_BYTES`), more than a test thread's default stack, so
/// the router runs on threads sized as the server sizes its own.
#[test]
fn repo_refusals_answer_their_own_status() {
    run_on_engine_stack("facade-repo-refusal-status", repo_refusals);
}

/// One owner-signed facade call and its status, error code and body.
struct OwnerCaller {
    app: Router,
    vault: Arc<Vault>,
    issuer: HostSlipIssuer,
    slip: CapabilitySlip,
    token: String,
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

async fn repo_refusals() {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("facade-repo-refusal-status-owner".into()),
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
    let caller = OwnerCaller {
        app: build_app(server),
        vault: Arc::clone(&vault),
        issuer,
        slip,
        token,
    };

    // The owner holds no repo Grant of its own, so the holder's checkout door
    // refuses it at the Grant check, before any id it names is resolved.
    let (status, code, body) = caller
        .call(
            "vault.code.checkout.holder.bind",
            &json!({
                "repo": EntityId::now().to_hex(),
                "ref": "refs/heads/main",
                "checkout": EntityId::now().to_hex(),
                "epoch": 1,
            }),
        )
        .await;
    assert_eq!(
        (status, code.as_deref()),
        (StatusCode::FORBIDDEN, Some("repo_no_membership")),
        "a caller no Grant admits to the repo: {body}"
    );

    // No run is registered in this fresh server: the observe door is routed,
    // and its live-run guard refuses the unknown run before the engine reads.
    let (status, code, body) = caller
        .call(
            "vault.repo.symbols.observe",
            &json!({
                "live_run": "lr1.11111111111111111111111111111111.22222222222222222222222222222222",
                "spec": {"work": EntityId::now().to_hex()},
            }),
        )
        .await;
    assert_eq!(
        (status, code.as_deref()),
        (StatusCode::FORBIDDEN, Some("live_run_unavailable")),
        "an unknown live run at vault.repo.symbols.observe: {body}"
    );

    // `vault.repo.proposal_resolve` (row PROPOSAL-DECLARATION-QUEUE-BINDING)
    // is a routed run door too: the public mirror of the native resolution.
    let (status, code, body) = caller
        .call(
            "vault.repo.proposal_resolve",
            &json!({
                "live_run": "lr1.11111111111111111111111111111111.22222222222222222222222222222222",
                "spec": {
                    "work": EntityId::now().to_hex(),
                    "branch_subject": EntityId::now().to_hex(),
                    "conflict": EntityId::now().to_hex(),
                    "branch": "refs/heads/main",
                    "path": "math.rs",
                    "content": [],
                    "message": "a resolution",
                },
            }),
        )
        .await;
    assert_eq!(
        (status, code.as_deref()),
        (StatusCode::FORBIDDEN, Some("live_run_unavailable")),
        "an unknown live run at vault.repo.proposal_resolve: {body}"
    );
}
