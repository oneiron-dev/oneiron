#![cfg(oneiron_test_support)]
//! [CORE-BATCH-HOSTED-ROOT-UNBOUND-LANE] (FIX-LIST:26197): the hosted
//! operator's root acts as nobody, so its core batch write keeps the typed
//! support-grant refusal instead of writing unbound (owner ruling "A +
//! support", 2026-10-18). `core_write_lane`
//! (src/api/facade/core_write_doors.rs) answered `Unbound` for that root:
//! its read is refused typed, and the owner-grade check below swallowed the
//! refusal. The facade door `POST /v1/core/facade/vault.batch` runs no host
//! check before its door, so the root's batch committed 200 there.
//!
//! - `hosted_root_batch_over_facade_is_refused_typed` (red on main): the
//!   hosted root's facade batch is 403 `HOST_ACTION_REQUIRES_SUPPORT_GRANT`
//!   and writes nothing.
//! - `self_host_root_batch_still_writes` (control): the self-host root's
//!   facade batch still commits 200, exactly as today.
//! - `hosted_root_batch_over_rest_stays_refused` (companion pin): the row's
//!   named route `POST /v1/core/batch` stays 403 typed for the hosted root
//!   (already refused via `rest_action_bound`, FIX 8210).
//!
//! The hosted fixture roots a `Hosted`-posture vault and calls under its
//! root slip with the issuer's holder proof (tests/inquiry_federation.rs);
//! the vault shape and the engine-stack driver follow
//! tests/gate_pin_core_write_lane.rs.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --test
//! core_batch_hosted_root_unbound_lane`.

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::Request;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, holder_proof_challenge};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{
    EntityId, HostingPrivacyPosture, Vault, VaultConfig, VaultDataKeyCustody, VaultPrivacyConfig,
};
use oneiron_server::{
    ENGINE_THREAD_STACK_BYTES, build_app, config::SyncServerConfig, server::SyncServer,
};
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// One served vault under its host root slip: the router, the slip and its
/// token, and the issuer that signs the root's holder proofs.
struct Fixture {
    app: Router,
    vault: Arc<Vault>,
    issuer: HostSlipIssuer,
    root: CapabilitySlip,
    root_token: String,
    _dir: tempfile::TempDir,
}

impl Fixture {
    /// A hosted vault: the operator holds a KMS key reference, so its root
    /// acts as nobody.
    fn hosted() -> TestResult<Self> {
        Self::open(true)
    }

    /// A self-hosted vault: its root acts as the owner, as today.
    fn self_host() -> TestResult<Self> {
        Self::open(false)
    }

    fn open(hosted: bool) -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let mut config = VaultConfig::device();
        config.map_size = 32 * 1024 * 1024;
        config.dimensions = 4;
        config.embedding_model = None;
        if hosted {
            config.privacy = VaultPrivacyConfig {
                posture: HostingPrivacyPosture::Hosted,
                data_key_custody: VaultDataKeyCustody::HostManagedKms {
                    key_ref: "kms://example/test-host-key".to_owned(),
                },
            };
        }
        let vault = Arc::new(Vault::open_owned(dir.path(), config)?);

        // HTTP trusts the logged issuer of each mint, not auth_secret, as in
        // tests/gate_pin_core_write_lane.rs. Root the vault explicitly.
        let issuer = HostSlipIssuer::from_secret(b"oneiron-test-core-batch-hosted-root")?;
        let root = vault.ensure_host_root_slip(&issuer)?;
        let root_token = root.to_token()?;

        let server = Arc::new(SyncServer::new(vault.clone(), SyncServerConfig::default())?);
        Ok(Self {
            app: build_app(server),
            vault,
            issuer,
            root,
            root_token,
            _dir: dir,
        })
    }

    /// The root slip's holder proof for one call, signed by the issuer that
    /// minted it (tests/inquiry_federation.rs).
    fn root_binding(&self) -> TestResult<String> {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let signature = hex(&self.issuer.binding_proof(&self.root, &challenge)?);
        Ok(json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string())
    }

    /// The root's batch call to `uri`, putting one PERSON at a fresh id.
    /// Returns the status, the body, and the id the put named.
    async fn post_batch(&self, uri: &str) -> TestResult<(u16, Value, EntityId)> {
        let id = EntityId::now();
        let input = json!({
            "entities": [{
                "id": id.to_hex(),
                "entity_type": ENTITY_TYPE_PERSON,
                "body": { "name": "hosted root probe" },
            }],
        });
        let request = Request::builder()
            .method("POST")
            .uri(uri)
            .header("authorization", format!("Bearer {}", self.root_token))
            .header("x-oneiron-binding", self.root_binding()?)
            .header("content-type", "application/json")
            .body(Body::from(input.to_string()))?;
        let response = self.app.clone().oneshot(request).await?;
        let status = response.status().as_u16();
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await?)?;
        Ok((status, body, id))
    }
}

/// Runs `test` as the server's binary runs its app: on a multi-thread runtime
/// whose threads have the engine's stack, driven from a thread that has it
/// too (tests/gate_pin_core_write_lane.rs).
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

#[test]
fn hosted_root_batch_over_facade_is_refused_typed() -> TestResult {
    on_engine_stack(hosted_root_batch_over_facade_is_refused_typed_async)
}

async fn hosted_root_batch_over_facade_is_refused_typed_async() -> TestResult {
    let fixture = Fixture::hosted()?;
    let (status, body, id) = fixture.post_batch("/v1/core/facade/vault.batch").await?;
    assert_eq!(status, 403, "{body}");
    assert_eq!(
        body["error"]["code"].as_str(),
        Some("HOST_ACTION_REQUIRES_SUPPORT_GRANT"),
        "{body}"
    );
    assert!(
        fixture.vault.get_entity_type(&id)?.is_none(),
        "the refused batch wrote nothing: {body}"
    );
    Ok(())
}

#[test]
fn self_host_root_batch_still_writes() -> TestResult {
    on_engine_stack(self_host_root_batch_still_writes_async)
}

async fn self_host_root_batch_still_writes_async() -> TestResult {
    let fixture = Fixture::self_host()?;
    let (status, body, id) = fixture.post_batch("/v1/core/facade/vault.batch").await?;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["count"], 1, "{body}");
    assert_eq!(
        fixture.vault.get_entity_type(&id)?,
        Some(ENTITY_TYPE_PERSON)
    );
    Ok(())
}

#[test]
fn hosted_root_batch_over_rest_stays_refused() -> TestResult {
    on_engine_stack(hosted_root_batch_over_rest_stays_refused_async)
}

async fn hosted_root_batch_over_rest_stays_refused_async() -> TestResult {
    let fixture = Fixture::hosted()?;
    let (status, body, id) = fixture.post_batch("/v1/core/batch").await?;
    assert_eq!(status, 403, "{body}");
    assert_eq!(
        body["error"]["code"].as_str(),
        Some("HOST_ACTION_REQUIRES_SUPPORT_GRANT"),
        "{body}"
    );
    assert!(
        fixture.vault.get_entity_type(&id)?.is_none(),
        "the refused batch wrote nothing: {body}"
    );
    Ok(())
}
