#![cfg(oneiron_test_support)]
//! L3-30 (canon ARCH-0044:471): an LFS upload whose body was received and
//! spooled, but whose install waited past `limits.queue_wait_timeout_ms` for
//! room in memory, is refused with a 503 of its own that says the object was
//! not stored. Not the shared pre-start text "nothing was started", which is
//! false once the body has been read. The installs line is held whole
//! through `oneiron_server::test_doors::lfs_install_line`, as installs in
//! flight would hold it.
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support
//! --test git_lfs_install_wait_out`.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::Request;
use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{CapabilitySlip, MachineRole, holder_proof_challenge};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::origin::lfs::LfsOid;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_server::config::{LimitsConfig, SyncServerConfig};
use oneiron_server::test_doors::lfs_install_line::hold_whole_install_line;
use oneiron_server::{ENGINE_THREAD_STACK_BYTES, build_app, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The queue wait every wait for room carries.
const WAIT_MS: u64 = 400;
const OBJECT: &[u8] = b"an object whose install waits for room in memory";

struct Fixture {
    app: Router,
    server: Arc<SyncServer>,
    vault: Arc<Vault>,
    writer: CapabilitySlip,
    key: SigningKey,
    _dir: tempfile::TempDir,
}

impl Fixture {
    /// A rooted vault behind the server, with a short queue wait, and a
    /// distinct person's `core:read` + `core:write` slip minted under the
    /// vault's logged issuer: a registered principal, as the LFS write gate
    /// requires.
    fn new() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        let root = vault.ensure_host_root_slip(&issuer)?;
        let person = EntityId::now();
        vault.put_entity(
            &person,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"a person who uploads",
        )?;
        let key = SigningKey::from_bytes(&[0x65; 32]);
        let mut claims = root.claims.clone();
        claims.parent_id = None;
        claims.slip_id = [0x65; 32];
        claims.holder_ref = person.to_hex();
        claims.binding_key = key.verifying_key().to_bytes();
        claims.actor_class = Some("human".to_owned());
        claims.scope = Scope::top();
        claims.scope.verbs = ScopeAxis::Some(BTreeSet::from([
            "core:read".to_owned(),
            "core:write".to_owned(),
        ]));
        let writer = vault.mint_capability_slip(&issuer, claims)?;
        let server = Arc::new(SyncServer::new(
            vault.clone(),
            SyncServerConfig {
                auth_secret: Some("git-lfs-install-wait-out".into()),
                limits: LimitsConfig {
                    queue_wait_timeout_ms: WAIT_MS,
                    ..LimitsConfig::default()
                },
                ..Default::default()
            },
        )?);
        Ok(Self {
            app: build_app(Arc::clone(&server)),
            server,
            vault,
            writer,
            key,
            _dir: dir,
        })
    }

    /// One LFS upload of `bytes` under the writer's slip and a fresh holder
    /// proof, its size declared: the HTTP status, its `Retry-After` and the
    /// body.
    async fn put(&self, bytes: &[u8]) -> TestResult<(u16, Option<String>, Value)> {
        let oid = LfsOid::digest(bytes).to_hex();
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let signature = self
            .key
            .sign(&self.writer.binding_transcript(&challenge)?)
            .to_bytes();
        let binding = json!({
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": hex(&signature),
        });
        let request = Request::put(format!("/git/notes/info/lfs/objects/{oid}"))
            .header("host", "origin.invalid")
            .header(
                "authorization",
                format!("Bearer {}", self.writer.to_token()?),
            )
            .header("x-oneiron-binding", binding.to_string())
            .header("content-type", "application/octet-stream")
            .header("content-length", bytes.len())
            .body(Body::from(bytes.to_vec()))?;
        let response = self.app.clone().oneshot(request).await?;
        let status = response.status().as_u16();
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let bytes = to_bytes(response.into_body(), usize::MAX).await?;
        let body = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        Ok((status, retry_after, body))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Runs `test` as the server's binary runs its app: on a multi-thread runtime
/// whose threads have the engine's stack, driven from a thread that has it
/// too (`ENGINE_THREAD_STACK_BYTES`). The upload's worker waits for its
/// install room on this runtime.
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

#[test]
fn an_upload_whose_install_waits_out_its_room_says_the_object_was_not_stored() -> TestResult {
    on_engine_stack(install_wait_out)
}

async fn install_wait_out() -> TestResult {
    let fixture = Fixture::new()?;
    let held = hold_whole_install_line(&fixture.server)
        .await
        .ok_or("FIXTURE: the installs line is free at the start")?;

    let started = Instant::now();
    let (status, retry_after, body) = fixture.put(OBJECT).await?;
    let waited = started.elapsed();
    // FIXTURE: the upload passed the gate, its body was read, and its install
    // waited out the held line.
    assert_eq!(
        status, 503,
        "FIXTURE: the upload's install waits out the held line: {body}"
    );
    assert!(
        waited >= Duration::from_millis(WAIT_MS),
        "FIXTURE: the upload waited its deadline (it waited {waited:?}): {body}"
    );
    assert_eq!(retry_after.as_deref(), Some("1"), "{body}");
    assert_eq!(
        fixture.vault.lfs_object(LfsOid::digest(OBJECT))?,
        None,
        "nothing was stored: {body}"
    );

    let message = body["message"]
        .as_str()
        .ok_or("the refusal states its message")?;
    assert!(
        !message.contains("nothing was started"),
        "a spooled upload's refusal does not say nothing was started: {message}"
    );
    assert!(
        message.contains("not stored"),
        "it says the object was not stored: {message}"
    );
    drop(held);
    Ok(())
}
