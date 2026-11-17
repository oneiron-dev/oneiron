//! SUBSTRATE-READ-ATTENUATED-OWNER-CREDENTIAL-SERVER-TEST (FIX-LIST 23258):
//! an owner slip attenuated to verbs={read} is FORBIDDEN the five substrate
//! reads a server door serves: vault.settings.learning,
//! vault.settings.snapshot_read, vault.learning.read, vault.retrieval.runs
//! and vault.projects.goal.get. The attenuated slip fails the owner proof,
//! so each door judges it by its Steward grant alone, as anyone's; the
//! owner holds no such grant, so every read is refused without saying what
//! the rows hold (the engine half, #7057). The owner's own full slip reads
//! all five, as before.
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --test substrate_read_attenuated_owner_slip`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use ed25519_dalek::SigningKey;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, SlipCaveat, holder_proof};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_server::{
    ENGINE_THREAD_STACK_BYTES, build_app, config::SyncServerConfig, server::SyncServer,
};
use serde_json::{Value, json};
use tower::ServiceExt;

/// A distinct slip id for each credential a test mints.
fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

/// The key every credential here binds; the holder proves it per request.
fn holder_key() -> SigningKey {
    SigningKey::from_bytes(&[0x53; 32])
}

/// A served device vault: its owner, its host issuer, and the server.
struct Served {
    _dir: tempfile::TempDir,
    server: Arc<SyncServer>,
    vault: Arc<Vault>,
    issuer: HostSlipIssuer,
    owner: EntityId,
}

fn served() -> Served {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("vault"));
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("substrate-read-attenuated-owner".to_owned()),
                ..Default::default()
            },
        )
        .expect("a server"),
    );
    let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    Served {
        _dir: dir,
        server,
        vault,
        issuer,
        owner,
    }
}

impl Served {
    /// The owner's own slip, holding the whole vault: owner-grade, as a
    /// mint is before its holder attenuates it.
    fn owner_slip(&self) -> CapabilitySlip {
        let mut claims = self
            .vault
            .ensure_host_root_slip(&self.issuer)
            .expect("the host root slip")
            .claims;
        claims.slip_id = next_slip_id();
        claims.parent_id = None;
        claims.holder_ref = self.owner.to_hex();
        claims.actor_class = Some("human".to_owned());
        claims.binding_key = holder_key().verifying_key().to_bytes();
        claims.scope = Scope::top();
        self.vault
            .mint_capability_slip(&self.issuer, claims)
            .expect("the owner's slip")
    }

    /// The owner's own slip, narrowed by its holder to `read`: the owner
    /// proof refuses it, so the substrate doors judge it by its grant
    /// alone.
    fn owner_read_slip(&self) -> CapabilitySlip {
        let mut slip = self.owner_slip();
        let mut narrowed = Scope::top();
        narrowed.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
        slip.attenuate(
            SlipCaveat {
                scope: Some(narrowed),
                ..Default::default()
            },
            &holder_key(),
        )
        .expect("the owner narrows its own slip to read");
        assert!(!slip.caveats.is_empty(), "the owner's slip is caveated");
        slip
    }

    /// `slip` posts `body` to the facade verb `verb`: the status and the
    /// body.
    async fn facade(&self, slip: &CapabilitySlip, verb: &str, body: Value) -> (StatusCode, Value) {
        let binding =
            holder_proof(slip, &holder_key(), self.vault.now_recorded_at()).expect("holder proof");
        let token = slip.to_token().expect("token");
        let response = build_app(Arc::clone(&self.server))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/core/facade/{verb}"))
                    .header("Authorization", format!("Bearer {token}"))
                    .header("Content-Type", "application/json")
                    .header("x-oneiron-binding", binding.to_string())
                    .body(Body::from(body.to_string()))
                    .expect("request"),
            )
            .await
            .expect("response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1_048_576)
            .await
            .expect("response body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }
}

/// The five substrate reads, each with a body its door parses: an empty
/// vault answers the owner on each.
fn substrate_reads(owner: EntityId) -> Vec<(&'static str, Value)> {
    vec![
        ("vault.settings.learning", json!({})),
        ("vault.settings.snapshot_read", json!({})),
        (
            "vault.learning.read",
            json!({"cell": {
                "subject": owner.to_hex(),
                "predicate": "learning.edit_cost",
                "executor": "substrate-probe",
                "consent_scope": "substrate-probe",
            }}),
        ),
        ("vault.retrieval.runs", json!({})),
        (
            "vault.projects.goal.get",
            json!({"project_ref": EntityId::now().to_hex()}),
        ),
    ]
}

/// The door's FORBIDDEN: the attenuated owner slip reached the substrate
/// door and was judged by its grant alone.
fn assert_substrate_refused(verb: &str, status: StatusCode, body: &Value) {
    assert_eq!(status, StatusCode::FORBIDDEN, "{verb}: {body}");
    assert_eq!(body["error"]["code"], "FORBIDDEN", "{verb}: {body}");
    let message = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("Steward grant"),
        "{verb}: the refusal judges the caller's grant: {body}"
    );
}

/// Runs one served case on threads that have the engine's native stack, as
/// `oneiron serve` runs its doors: a generated dispatch frame is larger than
/// a libtest thread's stack in a dev build (FIX 16372).
fn on_engine_stack<F>(case: impl FnOnce() -> F + Send + 'static)
where
    F: std::future::Future<Output = ()>,
{
    let thread = std::thread::Builder::new()
        .stack_size(ENGINE_THREAD_STACK_BYTES)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(ENGINE_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(case());
        })
        .expect("engine-stack thread");
    if let Err(panic) = thread.join() {
        std::panic::resume_unwind(panic);
    }
}

#[test]
fn attenuated_owner_slip_is_forbidden_the_substrate_reads() {
    on_engine_stack(|| async {
        let fx = served();
        let slip = fx.owner_read_slip();
        for (verb, body) in substrate_reads(fx.owner) {
            let (status, reply) = fx.facade(&slip, verb, body).await;
            assert_substrate_refused(verb, status, &reply);
        }
    });
}

#[test]
fn owner_slip_reads_the_substrate_reads() {
    on_engine_stack(|| async {
        let fx = served();
        let slip = fx.owner_slip();
        for (verb, body) in substrate_reads(fx.owner) {
            let (status, reply) = fx.facade(&slip, verb, body).await;
            assert_eq!(status, StatusCode::OK, "{verb}: {reply}");
        }
    });
}
