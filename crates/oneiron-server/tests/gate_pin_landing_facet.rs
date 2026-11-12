#![cfg(oneiron_test_support)]
//! OPUS-T0-F gate pins, PR 4 (Engine task 12 Nov 19:38): green pins for the
//! write gate G103 of OPUS-GATECENSUS's DEEP list (census/GATE-CENSUS.md,
//! class GAP-PASSES: real callers pass the gate today, and no running test
//! drove it from a door). G103 is `landing_facet`
//! (src/api/write_facet.rs): where a write by a credential narrowed to some
//! facets lands. Each test drives the facade door a real client uses,
//! `POST /v1/core/facade/tasks.create`, with a facet-narrowed credential,
//! and reads back the facet the TASK was born in. A pin that goes red is a
//! live refusal of a real caller (GAP-BROKEN).
//!
//! Each test name starts with the census id, so `-- g103_` runs these pins.
//!
//! - A paired credential with no session lands its TASK in the write facet
//!   the owner picked at pairing.
//! - A session named in `x-oneiron-session` whose facet the credential reads
//!   places the TASK in that facet, over the paired write facet.
//! - A credential never paired with a write facet lands its TASK in the
//!   smallest facet it reads.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features
//! oneiron/test-support,oneiron/test-hooks,oneiron-broker/test-support,tokio/test-util
//! --test gate_pin_landing_facet`.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::Request;
use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    CapabilitySlip, HostSlipIssuer, PairingPrincipal, holder_proof_challenge,
    pairing_binding_transcript,
};
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
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

/// A vault with two facets, a PERSON who reads both, and two of that
/// person's credentials narrowed to them: `paired` redeemed from the
/// owner's pairing link with `write` as its write facet, and `unpaired`
/// minted with no write facet. `write` is the larger facet id, so the
/// smallest-facet fallback is the wrong answer for a paired write.
struct Fixture {
    app: Router,
    vault: Arc<Vault>,
    smallest: EntityId,
    write: EntityId,
    paired: Credential,
    unpaired: Credential,
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
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"a member of the shared vault",
        )?;
        let mut set = BTreeSet::new();
        for name in [&b"work"[..], &b"home"[..]] {
            let facet = EntityId::now();
            vault.put_entity(
                &facet,
                oneiron::registry::ENTITY_TYPE_FACET,
                TimeRange { start: 1, end: 1 },
                1,
                name,
            )?;
            set.insert(ScopeId(facet));
        }
        let smallest = set.first().ok_or("two facets")?.0;
        let write = set.last().ok_or("two facets")?.0;
        let mut scope = Scope::top();
        scope.facets = ScopeAxis::Some(set);

        // HTTP trusts the logged issuer of each mint, not auth_secret, as in
        // tests/run_reader_record_scope.rs. Root the vault explicitly.
        let issuer = HostSlipIssuer::from_secret(b"oneiron-test-gate-pin-landing-facet")?;
        let root = vault.ensure_host_root_slip(&issuer)?;
        let holder = person.to_hex();

        // The owner's pairing link names the person and the write facet; the
        // person's connection redeems it with its own binding key.
        let link = vault.issue_pairing_link_for_principal(
            &issuer,
            scope.clone(),
            3600,
            PairingPrincipal {
                holder_ref: Some(holder.clone()),
                actor_class: Some("human".to_owned()),
                write_facet: Some(write.to_hex()),
                ..PairingPrincipal::default()
            },
        )?;
        let key = SigningKey::from_bytes(&[0x71; 32]);
        let binding = key.verifying_key().to_bytes();
        let signature = key.sign(&pairing_binding_transcript(&link.code, &binding, &holder)?);
        let paired = Credential {
            slip: vault.redeem_pairing_link(
                &issuer,
                &link.code,
                &holder,
                binding,
                &signature.to_bytes(),
            )?,
            key,
        };

        let key = SigningKey::from_bytes(&[0x72; 32]);
        let mut claims = root.claims;
        claims.parent_id = None;
        claims.holder_ref = holder;
        claims.binding_key = key.verifying_key().to_bytes();
        claims.actor_class = Some("human".to_owned());
        claims.scope = scope;
        claims.slip_id = [0x72; 32];
        let unpaired = Credential {
            slip: vault.mint_capability_slip(&issuer, claims)?,
            key,
        };

        let server = Arc::new(SyncServer::new(vault.clone(), SyncServerConfig::default())?);
        Ok(Self {
            app: build_app(server),
            vault,
            smallest,
            write,
            paired,
            unpaired,
            _dir: dir,
        })
    }

    /// A SESSION whose mode names `facet`, as a session in that facet's
    /// mode is stored.
    fn session_in(&self, facet: EntityId) -> TestResult<EntityId> {
        let session = EntityId::now();
        self.vault
            .batch()
            .put(
                &session,
                oneiron::registry::ENTITY_TYPE_SESSION,
                TimeRange { start: 1, end: 1 },
                1,
                &rmp_serde::to_vec_named(&json!({ "facet_ref": facet.to_hex() }))?,
            )
            .commit()?;
        Ok(session)
    }

    /// The client's `tasks.create` call with `credential`, its holder proof,
    /// and the session header when `session` names one. Returns the TASK the
    /// call created, or the status and body of any other answer.
    async fn create_task(
        &self,
        credential: &Credential,
        title: &str,
        session: Option<EntityId>,
    ) -> TestResult<EntityId> {
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
        let mut request = Request::builder()
            .method("POST")
            .uri("/v1/core/facade/tasks.create")
            .header(
                "authorization",
                format!("Bearer {}", credential.slip.to_token()?),
            )
            .header("x-oneiron-binding", binding.to_string())
            .header("content-type", "application/json");
        if let Some(session) = session {
            request = request.header("x-oneiron-session", session.to_hex());
        }
        let input = json!({
            "spec": { "title": title, "description": "a gate pin's task", "lane": "gate-pins" },
            "label": title,
        });
        let response = self
            .app
            .clone()
            .oneshot(request.body(Body::from(input.to_string()))?)
            .await?;
        let status = response.status().as_u16();
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await?)?;
        if status != 200 {
            return Err(format!("tasks.create answered {status}: {body}").into());
        }
        let task = body["task_ref"]
            .as_str()
            .ok_or_else(|| format!("tasks.create named no TASK: {body}"))?;
        Ok(EntityId::from_hex(task)?)
    }

    /// The facets of the credential's set that `task` was born in.
    fn landed(&self, task: &EntityId) -> TestResult<Vec<EntityId>> {
        let mut landed = Vec::new();
        for facet in [self.smallest, self.write] {
            if self
                .vault
                .row_in_facets(task, &ScopeAxis::Some(BTreeSet::from([ScopeId(facet)])))?
            {
                landed.push(facet);
            }
        }
        Ok(landed)
    }
}

/// Runs `test` as the server's binary runs its app: on a multi-thread runtime
/// whose threads have the engine's stack, driven from a thread that has it
/// too (tests/run_reader_record_scope.rs). The generated facade dispatch's
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
fn g103_a_paired_credentials_task_lands_in_its_write_facet() -> TestResult {
    on_engine_stack(paired_credential_lands_in_its_write_facet)
}

async fn paired_credential_lands_in_its_write_facet() -> TestResult {
    let fixture = Fixture::new()?;
    let task = fixture
        .create_task(&fixture.paired, "a paired task", None)
        .await?;
    assert_eq!(fixture.landed(&task)?, [fixture.write]);
    Ok(())
}

#[test]
fn g103_a_session_header_lands_the_task_in_the_sessions_facet() -> TestResult {
    on_engine_stack(session_header_lands_in_the_sessions_facet)
}

async fn session_header_lands_in_the_sessions_facet() -> TestResult {
    let fixture = Fixture::new()?;
    // The session's facet is not the paired write facet: the session places.
    let session = fixture.session_in(fixture.smallest)?;
    let task = fixture
        .create_task(&fixture.paired, "a task in a session", Some(session))
        .await?;
    assert_eq!(fixture.landed(&task)?, [fixture.smallest]);
    Ok(())
}

#[test]
fn g103_an_unpaired_credentials_task_lands_in_the_smallest_facet() -> TestResult {
    on_engine_stack(unpaired_credential_lands_in_the_smallest_facet)
}

async fn unpaired_credential_lands_in_the_smallest_facet() -> TestResult {
    let fixture = Fixture::new()?;
    let task = fixture
        .create_task(&fixture.unpaired, "an unpaired task", None)
        .await?;
    assert_eq!(fixture.landed(&task)?, [fixture.smallest]);
    Ok(())
}
