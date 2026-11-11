//! Connect host faults keep their server status while invalid peer proofs remain request errors.

#![cfg(unix)]

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use oneiron::authority::{CapabilitySlip, HostSlipIssuer};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{
    ENGINE_THREAD_STACK_BYTES, build_app, config::SyncServerConfig, server::SyncServer,
};
use serde_json::{Value, json};
use std::fs::{self, DirBuilder, Permissions};
use std::future::Future;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tower::ServiceExt;

struct OwnerClient {
    app: Router,
    vault: Arc<Vault>,
    issuer: HostSlipIssuer,
    slip: CapabilitySlip,
    token: String,
}

impl OwnerClient {
    fn new(path: &Path) -> Self {
        let vault = Arc::new(Vault::open(path, VaultConfig::device()).expect("open fresh vault"));
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        let server = Arc::new(
            SyncServer::new(
                Arc::clone(&vault),
                SyncServerConfig {
                    auth_secret: Some("connect-host-fault-owner".into()),
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

    async fn success(&self, path: &str, input: Value) -> Value {
        let (status, body) = self.post(path, input).await;
        assert_eq!(status, StatusCode::OK, "{path}: {body}");
        body
    }

    async fn world(&self, name: &str) -> String {
        let body = self
            .success(
                "/v1/core/facade/vault.structural.put",
                json!({
                    "kind": "WORLD",
                    "body": {"name": name, "kind": "fictional"},
                    "occurred_at": self.vault.now_recorded_at(),
                    "text_fields": [{"field": "name", "value": name}]
                }),
            )
            .await;
        body["id_hex"].as_str().expect("new world id").to_owned()
    }

    async fn status(&self) -> Value {
        self.success("/v1/core/facade/vault.federation.status", json!({}))
            .await
    }
}

struct ConnectFixture {
    local: OwnerClient,
    peer: OwnerClient,
    grant: Value,
    offer: Value,
    directory: tempfile::TempDir,
}

async fn connect_fixture() -> ConnectFixture {
    let directory = tempfile::tempdir().expect("fresh Connect vaults");
    let local = OwnerClient::new(&directory.path().join("local"));
    let peer = OwnerClient::new(&directory.path().join("peer"));
    let local_id = local
        .success(
            "/v1/core/facade/vault.federation.connect.identity",
            json!({}),
        )
        .await;
    let peer_id = peer
        .success(
            "/v1/core/facade/vault.federation.connect.identity",
            json!({}),
        )
        .await;
    let local_world = local.world("local-shared-world").await;
    let peer_world = peer.world("peer-shared-world").await;
    let local_grant = local
        .success(
            "/v1/owner/federation/connect/grants",
            json!({"peer_vault": peer_id["vault"], "authority_scope": share_scope(&local_world)}),
        )
        .await;
    let peer_grant = peer
        .success(
            "/v1/owner/federation/connect/grants",
            json!({"peer_vault": local_id["vault"], "authority_scope": share_scope(&peer_world)}),
        )
        .await;
    let offer = peer
        .success(
            "/v1/owner/federation/connect/offer",
            json!({
                "peer_vault": local_id["vault"], "grant": peer_grant["grant"],
                "outbound": direction(&peer_world), "inbound": direction(&local_world)
            }),
        )
        .await;
    ConnectFixture {
        local,
        peer,
        grant: local_grant["grant"].clone(),
        offer,
        directory,
    }
}

fn direction(world: &str) -> Value {
    json!({
        "worlds": {"kind": "some", "values": [world]},
        "facets": {"kind": "all"}, "bands": {"kind": "all"}
    })
}

fn share_scope(world: &str) -> Value {
    json!({
        "worlds": {"kind": "some", "values": [world]},
        "facets": {"kind": "all"}, "bands": {"kind": "all"},
        "audience": {"kind": "all"}, "verbs": {"kind": "some", "values": ["read"]},
        "sensitivity": {"kind": "at_most", "value": "private"}
    })
}

fn custody_directory(vault_path: &Path) -> PathBuf {
    let path = oneiron::store::custody_container_path(vault_path).expect("custody container");
    if !path.exists() {
        DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .expect("create custody container");
    }
    path
}

struct ReadOnlyDirectory {
    path: PathBuf,
    permissions: Permissions,
}

impl ReadOnlyDirectory {
    fn new(path: PathBuf) -> Self {
        let permissions = fs::metadata(&path)
            .expect("directory permissions")
            .permissions();
        fs::set_permissions(&path, Permissions::from_mode(0o555)).expect("make custody read-only");
        let guard = Self { path, permissions };
        let probe = guard.path.join(EntityId::now().to_hex());
        match fs::write(&probe, b"permission probe") {
            Ok(()) => {
                fs::remove_file(&probe).expect("remove permission probe");
                panic!(
                    "read-only directory accepted a write; run this test without root or DAC override"
                );
            }
            Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied),
        }
        guard
    }
}

impl Drop for ReadOnlyDirectory {
    fn drop(&mut self) {
        // No panic here: a panic while unwinding aborts the test binary and
        // loses the failure text. A failed restore shows as the retry's 500.
        if let Err(error) = fs::set_permissions(&self.path, self.permissions.clone()) {
            eprintln!("restore {}: {error}", self.path.display());
        }
    }
}

fn on_engine_threads<F, Fut>(test: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = ()>,
{
    let run = std::thread::Builder::new()
        .name("connect-host-fault-status".into())
        .stack_size(ENGINE_THREAD_STACK_BYTES)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(ENGINE_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .expect("engine-sized test runtime")
                .block_on(test());
        })
        .expect("spawn engine-sized test thread");
    if let Err(panic) = run.join() {
        std::panic::resume_unwind(panic);
    }
}

#[test]
fn connect_host_fault_answers_internal_not_bad_request() {
    on_engine_threads(host_fault_status);
}

async fn host_fault_status() {
    let fixture = connect_fixture().await;
    let before = fixture.local.status().await;
    assert_eq!(before["pacts"], json!([]));
    let custody = custody_directory(&fixture.directory.path().join("local"));
    let guard = ReadOnlyDirectory::new(custody);
    // Accept validates the peer's real signature before installing its scope key.
    // Custody rejects 0555 as CorruptedIndex before publishing the new scope key.
    let (status, body) = fixture
        .local
        .post(
            "/v1/owner/federation/connect/accept",
            json!({"grant": fixture.grant, "offer": fixture.offer}),
        )
        .await;
    drop(guard);
    let after = fixture.local.status().await;
    assert_eq!(
        after["pacts"], before["pacts"],
        "failed accept must roll back its pact"
    );
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert_eq!(body["error"]["code"], "INTERNAL_SERVER_ERROR", "{body}");

    // With the host fault removed, the identical request must pass every input check.
    let accepted = fixture
        .local
        .success(
            "/v1/owner/federation/connect/accept",
            json!({"grant": fixture.grant, "offer": fixture.offer}),
        )
        .await;
    assert_eq!(accepted["status"], "Active");
    assert_eq!(fixture.peer.status().await["pacts"], json!([]));
}

#[test]
fn connect_invalid_peer_signature_stays_bad_request() {
    on_engine_threads(invalid_peer_signature_status);
}

async fn invalid_peer_signature_status() {
    let mut fixture = connect_fixture().await;
    fixture.offer["signature"] = Value::String("00".repeat(64));
    let (status, body) = fixture
        .local
        .post(
            "/v1/owner/federation/connect/accept",
            json!({"grant": fixture.grant, "offer": fixture.offer}),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], "BAD_REQUEST", "{body}");
    assert_eq!(fixture.local.status().await["pacts"], json!([]));
}
