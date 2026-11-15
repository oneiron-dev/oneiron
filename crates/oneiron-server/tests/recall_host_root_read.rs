//! The owner's host-root recall reads on a self-hosted vault
//! ([RECALL-HOST-ROOT-READ-REFUSED], FIX-LIST row 26232).
//!
//! `vault.recall` serves through `SyncServer::recall_home_listing`, whose
//! reader bound only the presented slip (`with_read_proof`). A self-hosted
//! root acts as the owner but its slip's holder is "host", not the owner,
//! so the read lane refused every host-root recall with 403 "the bound read
//! credential does not grant this actor a read". The reader now binds the
//! host action the one resolver names, as `credential_memory` does.
//!
//! Red at main: the self-host case answers 403. Guards (they pass there
//! too): on a hosted vault the same recall keeps its typed support-grant
//! refusal, another person's write-only slip keeps its 403, and a request
//! with no credential keeps its 401.
//!
//! Each case drives the real route in-process (`oneshot`, no TCP ports, no
//! sleeps, no models, no embedder).
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --test recall_host_root_read`.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use ed25519_dalek::SigningKey;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole, SlipCaveat, holder_proof};
use oneiron::edge::EdgeActorClass;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{EntityId, HostingPrivacyPosture, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{
    ENGINE_THREAD_STACK_BYTES, build_app, config::SyncServerConfig, server::SyncServer,
};
use serde_json::{Value, json};
use tower::ServiceExt;

const RECALL: &str = "/v1/core/facade/vault.recall";
/// The one word the owner's witnessed turn holds, which nothing else holds.
const TURN_WORD: &str = "quayside";

/// A distinct slip id for each credential a test mints.
fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

/// The key every minted person credential binds; the holder proves it per request.
fn holder_key() -> SigningKey {
    SigningKey::from_bytes(&[0x5B; 32])
}

struct Host {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
}

/// Runs `test` on an engine-sized stack and runtime, as the served doors
/// need more than a test thread's default stack.
fn run_on_engine_stack(name: &str, test: impl std::future::Future<Output = ()> + Send + 'static) {
    let run = std::thread::Builder::new()
        .name(name.into())
        .stack_size(ENGINE_THREAD_STACK_BYTES)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(ENGINE_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .expect("engine-sized test runtime")
                .block_on(test)
        })
        .expect("spawn the engine-sized test thread");
    if let Err(panic) = run.join() {
        std::panic::resume_unwind(panic);
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A served vault under `posture`, whose owner witnessed one turn holding
/// [`TURN_WORD`], with the install rooted and profiled as a serving start
/// enrols it.
fn host(posture: HostingPrivacyPosture) -> Host {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let mut config = VaultConfig::device();
    config.embedding_model = None;
    config.dimensions = 4;
    config.privacy.posture = posture;
    let vault = Arc::new(Vault::open(dir.path(), config).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    witness_turn(&vault, owner);
    vault.set_indexed_idle_delay_ms(0).expect("index delay");
    let published = vault
        .refresh_staged_indexed_at_idle(u64::MAX)
        .expect("index refresh");
    assert!(
        published.failed.is_empty(),
        "FIXTURE: the witnessed turn is indexed: {:?}",
        published.failed
    );
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("recall-host-root-read".into()),
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
    Host {
        _dir: dir,
        vault,
        app,
        issuer,
        owner_slip,
        owner_token,
    }
}

/// The owner's one turn, holding [`TURN_WORD`]. A base witness parses its
/// conversation ref as an entity ref, so the turn names a fresh conversation.
fn witness_turn(vault: &Vault, owner: EntityId) {
    vault
        .memory(owner, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: EntityId::now().to_hex(),
            turn_ref: None,
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: None,
                author: WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: format!("the ferry waits at the {TURN_WORD}"),
                metadata: None,
                is_visible: true,
                order: 0,
                parts: None,
                quote: None,
            }],
            occurred_at: vault.now_recorded_at(),
            assertions: Default::default(),
        })
        .expect("the owner's witnessed turn");
}

impl Host {
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

    /// `vault.recall` for `query` over actual HTTP, under `token` with its
    /// holder's proof: the status and the answer, which must be JSON.
    async fn recall(&self, token: &str, binding: &str, query: &str) -> (StatusCode, Value) {
        let request = Request::post(RECALL)
            .header("authorization", format!("Bearer {token}"))
            .header("x-oneiron-binding", binding)
            .header("content-type", "application/json")
            .body(Body::from(json!({"query": query, "limit": 10}).to_string()))
            .expect("recall request");
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("recall response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("recall response body");
        let answer: Value = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
            panic!(
                "{RECALL} answered no JSON: {}",
                String::from_utf8_lossy(&bytes)
            )
        });
        (status, answer)
    }

    /// `vault.recall` with no credential: the status and the answer.
    async fn recall_anonymous(&self, query: &str) -> (StatusCode, Value) {
        let request = Request::post(RECALL)
            .header("content-type", "application/json")
            .body(Body::from(json!({"query": query, "limit": 10}).to_string()))
            .expect("recall request");
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("recall response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("recall response body");
        let answer: Value = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
            panic!(
                "{RECALL} answered no JSON: {}",
                String::from_utf8_lossy(&bytes)
            )
        });
        (status, answer)
    }

    /// A slip this host mints `who` as a human, at the host root's own scope.
    fn slip_for(&self, who: EntityId) -> CapabilitySlip {
        let mut claims = self
            .vault
            .ensure_host_root_slip(&self.issuer)
            .expect("the host root slip")
            .claims;
        claims.slip_id = next_slip_id();
        claims.parent_id = None;
        claims.holder_ref = who.to_hex();
        claims.actor_class = Some("human".to_owned());
        claims.binding_key = holder_key().verifying_key().to_bytes();
        self.vault
            .mint_capability_slip(&self.issuer, claims)
            .expect("a slip")
    }

    /// `who`'s slip narrowed by its holder to `write` alone: no read scope.
    fn write_only_slip_for(&self, who: EntityId) -> CapabilitySlip {
        let mut slip = self.slip_for(who);
        let mut narrowed = Scope::top();
        narrowed.verbs = ScopeAxis::Some(BTreeSet::from(["write".to_owned()]));
        slip.attenuate(
            SlipCaveat {
                scope: Some(narrowed),
                ..Default::default()
            },
            &holder_key(),
        )
        .expect("the holder narrows its own slip");
        assert!(!slip.caveats.is_empty(), "the slip is caveated");
        slip
    }

    fn person(&self) -> EntityId {
        let id = EntityId::now();
        self.vault
            .put_entity(
                &id,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"human",
            )
            .expect("a live person");
        id
    }
}

fn items(pack: &Value) -> &[Value] {
    pack["items"].as_array().map(Vec::as_slice).unwrap_or(&[])
}

#[test]
fn host_root_recall_reads_owner_rows_on_self_host() {
    run_on_engine_stack("recall-host-root-self-host", async {
        let host = host(HostingPrivacyPosture::SelfHostLocal);
        let token = host.owner_token.clone();
        let binding = host.owner_binding();
        let (status, pack) = host.recall(&token, &binding, TURN_WORD).await;
        assert_eq!(status, StatusCode::OK, "{RECALL} answered {pack}");
        assert!(
            !items(&pack).is_empty(),
            "the witnessed turn's word finds it: {pack}",
        );
    });
}

#[test]
fn host_root_recall_stays_refused_on_hosted() {
    run_on_engine_stack("recall-host-root-hosted", async {
        let host = host(HostingPrivacyPosture::Hosted);
        let token = host.owner_token.clone();
        let binding = host.owner_binding();
        let (status, answer) = host.recall(&token, &binding, TURN_WORD).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{RECALL} answered {answer}");
        assert_eq!(
            answer["error"]["code"],
            Value::from("HOST_ACTION_REQUIRES_SUPPORT_GRANT"),
            "{answer}",
        );
    });
}

#[test]
fn recall_without_read_grant_stays_refused() {
    run_on_engine_stack("recall-no-read-grant", async {
        let host = host(HostingPrivacyPosture::SelfHostLocal);
        let other = host.person();
        let slip = host.write_only_slip_for(other);
        let token = slip.to_token().expect("person slip token");
        let binding = holder_proof(&slip, &holder_key(), host.vault.now_recorded_at())
            .expect("holder proof")
            .to_string();
        let (status, answer) = host.recall(&token, &binding, TURN_WORD).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{RECALL} answered {answer}");
        let (status, answer) = host.recall_anonymous(TURN_WORD).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{RECALL} answered {answer}"
        );
    });
}
