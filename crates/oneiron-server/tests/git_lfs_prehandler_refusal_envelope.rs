#![cfg(oneiron_test_support)]
//! A slip the owner revoked is refused at the binding door, before any route
//! runs. The git-LFS doors answer their own refusals in the typed
//! `{"error": ...}` envelope (their handlers return `EnvelopedApiError`), so
//! the binding door's refusal on an LFS path wears the same envelope as on a
//! `/v1/` path, not the bare `ApiError` body (E2E CODE-CUSTODY-06).
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --test git_lfs_prehandler_refusal_envelope`.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::Request;
use ed25519_dalek::{Signer, SigningKey};
use oneiron::agent_dispatch::DEFAULT_BASE_LOGICAL_ID;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, holder_proof_challenge};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_server::{
    ENGINE_THREAD_STACK_BYTES, build_app, config::SyncServerConfig, server::SyncServer,
};
use serde_json::Value;
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const LFS_BATCH: &str = "/git/notes/info/lfs/objects/batch";

struct Fixture {
    app: Router,
    vault: Arc<Vault>,
    issuer: HostSlipIssuer,
    slip: CapabilitySlip,
    key: SigningKey,
    _dir: tempfile::TempDir,
}

impl Fixture {
    /// One vault, rooted explicitly, and one read-scoped agent slip.
    fn new() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let mut config = VaultConfig::device();
        config.map_size = 32 * 1024 * 1024;
        config.dimensions = 4;
        config.embedding_model = None;
        let vault = Arc::new(Vault::open_owned(dir.path(), config)?);
        let (agent, _) = vault
            .get_seeded_agent_definition_by_logical_id(DEFAULT_BASE_LOGICAL_ID)?
            .ok_or("the default agent is seeded")?;
        let issuer = HostSlipIssuer::from_secret(b"oneiron-test-git-lfs-refusal-envelope")?;
        let root = vault.ensure_host_root_slip(&issuer)?;
        let key = SigningKey::from_bytes(&[0x71; 32]);
        let mut claims = root.claims;
        claims.parent_id = None;
        claims.holder_ref = agent.to_hex();
        claims.binding_key = key.verifying_key().to_bytes();
        claims.actor_class = Some("agent".to_owned());
        claims.scope = Scope::top();
        claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
        claims.slip_id = [0x71; 32];
        let slip = vault.mint_capability_slip(&issuer, claims)?;
        let server = Arc::new(SyncServer::new(vault.clone(), SyncServerConfig::default())?);
        Ok(Self {
            app: build_app(server),
            vault,
            issuer,
            slip,
            key,
            _dir: dir,
        })
    }

    /// Sends one request as the agent, with a fresh holder proof.
    async fn send(
        &self,
        method: &str,
        path: &str,
        input: Option<Value>,
    ) -> TestResult<(u16, Value)> {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let signature = self
            .key
            .sign(&self.slip.binding_transcript(&challenge)?)
            .to_bytes();
        let binding = serde_json::json!({
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": hex(&signature),
        });
        let builder = Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", format!("Bearer {}", self.slip.to_token()?))
            .header("x-oneiron-binding", binding.to_string());
        let request = match input {
            Some(input) => builder
                .header("content-type", "application/json")
                .body(Body::from(input.to_string()))?,
            None => builder.body(Body::empty())?,
        };
        let response = self.app.clone().oneshot(request).await?;
        let status = response.status().as_u16();
        let body = to_bytes(response.into_body(), usize::MAX).await?;
        Ok((status, serde_json::from_slice(&body)?))
    }
}

/// Runs `test` as the server's binary runs its app: on a multi-thread runtime
/// whose threads have the engine's stack, driven from a thread that has it
/// too (`ENGINE_THREAD_STACK_BYTES`).
fn on_engine_stack<F, Fut>(test: F) -> TestResult
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = TestResult>,
{
    let driver = std::thread::Builder::new()
        .stack_size(ENGINE_THREAD_STACK_BYTES)
        .spawn(move || -> Result<(), String> {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(ENGINE_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .map_err(|error| error.to_string())?
                .block_on(test())
                .map_err(|error| error.to_string())
        })?;
    match driver.join() {
        Ok(outcome) => Ok(outcome?),
        // A failed assertion fails the test with its own message.
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The binding door's 401 in the typed envelope, with no bare top-level code.
fn assert_enveloped_unauthorized(door: &str, status: u16, body: &Value) {
    assert_eq!(status, 401, "{door}: status={status}, body={body}");
    assert_eq!(
        body["error"]["code"], "UNAUTHORIZED",
        "{door}: the refusal wears the error envelope; body={body}"
    );
    assert!(
        body.get("code").is_none(),
        "{door}: no bare ApiError body; body={body}"
    );
}

#[test]
fn a_revoked_slip_is_refused_at_the_git_lfs_doors_in_their_error_envelope() -> TestResult {
    on_engine_stack(revoked_slip_at_the_git_lfs_doors)
}

async fn revoked_slip_at_the_git_lfs_doors() -> TestResult {
    let fixture = Fixture::new()?;
    // The slip is live: the binding door admits it.
    let (status, body) = fixture
        .send(
            "POST",
            "/v1/core/facade/self.actor",
            Some(serde_json::json!({})),
        )
        .await?;
    assert_eq!(status, 200, "a live slip reads its actor: body={body}");

    fixture
        .vault
        .revoke_capability_slip(&fixture.issuer, fixture.slip.claims.slip_id)?;

    // The LFS batch door and an LFS object door refuse the revoked slip in
    // the envelope their handlers use for every other refusal.
    let batch = serde_json::json!({
        "operation": "download",
        "transfers": ["basic"],
        "objects": [],
    });
    let (status, body) = fixture.send("POST", LFS_BATCH, Some(batch)).await?;
    assert_enveloped_unauthorized(LFS_BATCH, status, &body);
    let object = format!("/git/notes/info/lfs/objects/{}", "0".repeat(64));
    let (status, body) = fixture.send("GET", &object, None).await?;
    assert_enveloped_unauthorized(&object, status, &body);

    // The facade door's refusal of the same slip, unchanged.
    let (status, body) = fixture
        .send(
            "POST",
            "/v1/core/facade/self.actor",
            Some(serde_json::json!({})),
        )
        .await?;
    assert_enveloped_unauthorized("/v1/core/facade/self.actor", status, &body);
    Ok(())
}
