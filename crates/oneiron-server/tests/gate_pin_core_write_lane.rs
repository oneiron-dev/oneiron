#![cfg(oneiron_test_support)]
//! OPUS-T0-F gate pins, PR 9 (Engine NOTE 13 Nov 02:19): green pins for the
//! write gate G80 of OPUS-TRIAGECENSUS's census (census/TRIAGE.md, class
//! GAP-PASSES: real callers pass the gate today, and no running test drove
//! it from a door). G80 is `core_write_lane`
//! (src/api/facade/core_write_doors.rs): the read lane a core write from a
//! credential is held to. It refuses the write when the credential's read
//! is refused for any reason other than Unauthorized. Each test drives the
//! facade door a real client uses, `POST /v1/core/facade/vault.batch`, puts
//! one PERSON at a fresh id, and reads the row back. A pin that goes red is
//! a live refusal of a real caller (GAP-BROKEN).
//!
//! Each test name starts with the census id, so `-- g80_` runs these pins.
//!
//! - A credential that reads and writes writes under its own read lane.
//! - A write-only credential's read is refused Unauthorized, so it writes
//!   under the lane its target key gives.
//!
//! A put at a fresh id is admitted in every lane, so these pins prove the
//! gate lets each caller's write commit, not where a lane bounds it.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features
//! oneiron/test-support,oneiron/test-hooks,oneiron-broker/test-support,tokio/test-util
//! --test gate_pin_core_write_lane`.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::Request;
use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, holder_proof_challenge};
use oneiron::federation::ScopeAxis;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_server::{
    ENGINE_THREAD_STACK_BYTES, build_app, config::SyncServerConfig, server::SyncServer,
};
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Credential {
    slip: CapabilitySlip,
    key: SigningKey,
}

/// A vault with one PERSON and two of that person's credentials, minted from
/// the host root with its whole scope and only the verbs narrowed:
/// `reader` reads and writes, `writer` only writes.
struct Fixture {
    app: Router,
    vault: Arc<Vault>,
    reader: Credential,
    writer: Credential,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let mut config = VaultConfig::device();
        config.map_size = 32 * 1024 * 1024;
        config.dimensions = 4;
        config.embedding_model = None;
        let vault = Arc::new(Vault::open_owned(dir.path(), config)?);

        let person = EntityId::now();
        vault.put_entity(
            &person,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"a member of the shared vault",
        )?;

        // HTTP trusts the logged issuer of each mint, not auth_secret, as in
        // tests/gate_pin_landing_facet.rs. Root the vault explicitly.
        let issuer = HostSlipIssuer::from_secret(b"oneiron-test-gate-pin-core-write-lane")?;
        let root = vault.ensure_host_root_slip(&issuer)?;
        // The record-scope guard of `vault.batch` admits only a slip whose
        // verbs alone are narrowed, so each keeps the root's top scope.
        let mint = |seed: u8, verbs: &[&str]| -> TestResult<Credential> {
            let key = SigningKey::from_bytes(&[seed; 32]);
            let mut claims = root.claims.clone();
            claims.parent_id = None;
            claims.holder_ref = person.to_hex();
            claims.binding_key = key.verifying_key().to_bytes();
            claims.actor_class = Some("human".to_owned());
            claims.scope.verbs =
                ScopeAxis::Some(verbs.iter().map(|verb| (*verb).to_owned()).collect());
            claims.slip_id = [seed; 32];
            Ok(Credential {
                slip: vault.mint_capability_slip(&issuer, claims)?,
                key,
            })
        };
        let reader = mint(0x81, &["read", "write"])?;
        let writer = mint(0x82, &["write"])?;

        let server = Arc::new(SyncServer::new(vault.clone(), SyncServerConfig::default())?);
        Ok(Self {
            app: build_app(server),
            vault,
            reader,
            writer,
            _dir: dir,
        })
    }

    /// The client's `vault.batch` call with `credential` and its holder
    /// proof, putting one PERSON at a fresh id. Returns that id once the
    /// door answers 200 naming it, or the status and body of any other
    /// answer.
    async fn put_person(&self, credential: &Credential, name: &str) -> TestResult<EntityId> {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let signature = credential
            .key
            .sign(&credential.slip.binding_transcript(&challenge)?)
            .to_bytes();
        let binding = json!({
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": hex(&signature),
        });
        let id = EntityId::now();
        let input = json!({
            "entities": [{
                "id": id.to_hex(),
                "entity_type": ENTITY_TYPE_PERSON,
                "body": { "name": name },
            }],
        });
        let request = Request::builder()
            .method("POST")
            .uri("/v1/core/facade/vault.batch")
            .header(
                "authorization",
                format!("Bearer {}", credential.slip.to_token()?),
            )
            .header("x-oneiron-binding", binding.to_string())
            .header("content-type", "application/json")
            .body(Body::from(input.to_string()))?;
        let response = self.app.clone().oneshot(request).await?;
        let status = response.status().as_u16();
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await?)?;
        if status != 200 {
            return Err(format!("vault.batch answered {status}: {body}").into());
        }
        assert_eq!(body["count"], 1, "{body}");
        let written: BTreeSet<&str> = body["entities"]
            .as_array()
            .ok_or_else(|| format!("vault.batch named no entities: {body}"))?
            .iter()
            .filter_map(|entity| entity["id"].as_str())
            .collect();
        let id_hex = id.to_hex();
        assert_eq!(written, BTreeSet::from([id_hex.as_str()]), "{body}");
        Ok(id)
    }
}

/// Runs `test` as the server's binary runs its app: on a multi-thread runtime
/// whose threads have the engine's stack, driven from a thread that has it
/// too (tests/gate_pin_landing_facet.rs). The generated facade dispatch's
/// poll frame alone is over 11 MiB in a dev build.
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
fn g80_a_credential_that_reads_writes_a_batch_under_its_read() -> TestResult {
    on_engine_stack(reading_credential_writes_a_batch)
}

async fn reading_credential_writes_a_batch() -> TestResult {
    let fixture = Fixture::new()?;
    let id = fixture.put_person(&fixture.reader, "owen").await?;
    assert_eq!(
        fixture.vault.get_entity_type(&id)?,
        Some(ENTITY_TYPE_PERSON)
    );
    Ok(())
}

#[test]
fn g80_a_write_only_credential_writes_a_batch_under_its_target_key() -> TestResult {
    on_engine_stack(write_only_credential_writes_a_batch)
}

async fn write_only_credential_writes_a_batch() -> TestResult {
    let fixture = Fixture::new()?;
    let id = fixture.put_person(&fixture.writer, "yuki").await?;
    assert_eq!(
        fixture.vault.get_entity_type(&id)?,
        Some(ENTITY_TYPE_PERSON)
    );
    Ok(())
}
