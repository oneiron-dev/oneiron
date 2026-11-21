//! L9-15 PR 2 (I2-LOCAL; ARCH-0004 `#rerank-door-built`): a recall at high
//! sends its reranker the words of a row a device-only world keeps only when
//! the vault's model policy routes the reranker on this device alone. Here
//! the reranker seat's one rung is a managed llama.cpp worker row that
//! listens on a Unix socket of its own (`listen = "unix"`, PR 1 #7806), so
//! the seat's on-device view serves every rung of the seat and the recall
//! host runs on the device.
//!
//! - On that socket reranker the stub is sent the kept claim's words, the
//!   recall says `applied`, and the kept claim, which holds every word of the
//!   query, ranks first. Red on main: the host never runs on the device, so
//!   the kept claim reaches the stub empty and ranks last.
//! - A reranker over loopback HTTP is sent the kept claim empty: a loopback
//!   address alone is not the trust contract (control, main and head).
//! - A seat whose socket rung has an HTTP rung behind it is no on-device
//!   route: the view drops a rung of the seat, so the socket stub is sent the
//!   kept claim empty too (control, main and head).
//!
//! Each case recalls at high through `POST /v1/core/facade/vault.recall` as
//! the owner, from this device, in the kept claim's WORLD with base reality,
//! where a portable claim holds one word of the query. The stub
//! (`tests/fixtures/stub_rerank_uds.py`, standard-library Python) stands in
//! for the worker: the test door starts it in a supervisor's custody and
//! records it as the hosted row's current launch, as PR 1's
//! `supervised_rerank_socket` does.
#![cfg(any(target_os = "linux", target_os = "macos"))]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, State};
use axum::{
    Json, Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{HostSlipIssuer, holder_proof_challenge};
use oneiron::federation::Scope;
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_WORLD};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EntityId, TimeRange, Vault,
    VaultConfig,
};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::ai_host::AiHost;
use oneiron_server::build_app;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::config::models::ModelsConfig;
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::supervised_rerank::{
    SocketStub, permit_worker_launch, record_socket_launch,
};
use serde_json::{Value, json};
use tower::ServiceExt;

// The configured server secret that selects secret-based rooting at boot; it
// is config, not issuer key material.
const AUTH_SECRET: &str = "device-only-rerank-auth-secret";
/// The `listen = "unix"` worker row's id.
const WORKER: &str = "rerank-socket";
const QUERY: &str = "ferry leaves seven";
/// The claim the device-only world keeps: it holds every word of the query.
const KEPT: &str = "the ferry leaves at seven";
/// The portable claim in base reality: it holds one word of the query.
const PORTABLE: &str = "the ferry timetable hangs by the pier";

/// The worker host is one per process: each case builds the server's models
/// in its turn, so none replaces another's hosted rows.
static HOST_TURN: Mutex<()> = Mutex::new(());

/// The reranker as a reranker reads it: the claim's predicate, then its
/// words.
fn document(text: &str) -> String {
    format!("profile.note: {text}")
}

/// `[models]` whose reranker is `rungs`, beside the `house-rerank` provider
/// served by a managed llama.cpp worker on its own socket for the reranker
/// alone, and `extra` providers. Nothing is installed: the row's artifacts
/// are paths under `dir` that do not exist, so its supervisor never
/// launches, and the test door records the stub as its launch instead.
fn socket_models(dir: &Path, rungs: &str, extra: &str) -> ModelsConfig {
    let toml = format!(
        r#"
[providers.house-rerank]
kind = "local-openai-compat"
base_url = "http://127.0.0.1:18433" # testkit-lint: allow(fixed-port) config text: nothing binds or calls a provider its socket rows serve
revision = "v1"
timeout_secs = 20
{extra}
[roles.reranker]
rungs = [{rungs}]

[workers.{WORKER}]
model = "house-rerank:stub-reranker"
kind = "llama_cpp"
mode = "managed"
listen = "unix"
weights_manifest = "{weights}"
server = "{server}"
server_sha256 = "{sha}"
runtime_root = "{runtime}"

[dreamer]
enabled = false
"#,
        weights = dir.join("absent-weights.json").display(),
        server = dir.join("absent-server-binary").display(),
        sha = "0".repeat(64),
        runtime = dir.join("rt").display(),
    );
    ModelsConfig::from_toml(&toml, None)
        .unwrap_or_else(|error| panic!("FIXTURE: a listen = \"unix\" reranker row: {error:#}"))
}

/// `[models]` whose reranker is reached over loopback HTTP at `base_url`.
fn http_models(base_url: &str) -> ModelsConfig {
    let toml = format!(
        "[providers.rerank]\n\
         kind = \"local-openai-compat\"\n\
         base_url = \"{base_url}\"\n\
         [roles.reranker]\n\
         model = \"rerank:fake-reranker\"\n\
         [dreamer]\n\
         enabled = false\n"
    );
    ModelsConfig::from_toml(&toml, None)
        .unwrap_or_else(|error| panic!("FIXTURE: a loopback reranker: {error:#}"))
}

/// A loopback `/v1/rerank` that keeps each request and scores every
/// document 0.5.
#[derive(Clone, Default)]
struct Fake {
    calls: Arc<AtomicUsize>,
    seen: Arc<Mutex<Vec<Value>>>,
}

struct FakeReranker {
    base_url: String,
    fake: Fake,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for FakeReranker {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl FakeReranker {
    async fn start() -> Self {
        let fake = Fake::default();
        let app = Router::new()
            .route("/v1/rerank", axum::routing::post(fake_rerank))
            .with_state(fake.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("fake reranker listener");
        let addr = listener.local_addr().expect("fake reranker address");
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            base_url: format!("http://{addr}"),
            fake,
            task,
        }
    }

    fn calls(&self) -> usize {
        self.fake.calls.load(Ordering::SeqCst)
    }

    fn seen(&self) -> Vec<Value> {
        self.fake
            .seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

async fn fake_rerank(State(fake): State<Fake>, Json(body): Json<Value>) -> Json<Value> {
    fake.calls.fetch_add(1, Ordering::SeqCst);
    fake.seen
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(body.clone());
    let count = body["documents"].as_array().map_or(0, Vec::len);
    let results: Vec<Value> = (0..count)
        .map(|index| json!({"index": index, "relevance_score": 0.5}))
        .collect();
    Json(json!({
        "model": "fake-reranker-v1",
        "results": results,
        "usage": {"total_tokens": 10},
    }))
}

/// The stub on `socket`, logging to `log`, in a supervisor's custody; it is
/// listening when this returns.
async fn start_stub(socket: &Path, log: &Path) -> SocketStub {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/stub_rerank_uds.py");
    let stub = SocketStub::start(
        &PathBuf::from("python3"),
        &[
            script.display().to_string(),
            socket.display().to_string(),
            log.display().to_string(),
        ],
    )
    .expect("FIXTURE: the stub starts");
    // testkit-lint: allow(wall-clock) hang guard while the stub process binds its socket
    let started = Instant::now();
    while !socket.exists() {
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "FIXTURE: the stub bound {} within 20 s",
            socket.display()
        );
        // testkit-lint: allow(sleep) poll interval: the stub binds its socket in its own process
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    stub
}

/// The bodies of the `/v1/rerank` requests the stub at `log` was sent.
fn stub_rerank_bodies(log: &Path) -> Vec<Value> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("a JSON log line"))
        .filter(|line| line["method"] == "POST" && line["path"] == "/v1/rerank")
        .map(|line| line["body"].clone())
        .collect()
}

/// The documents one rerank request body sends.
fn documents(body: &Value) -> Vec<String> {
    body["documents"]
        .as_array()
        .unwrap_or_else(|| panic!("a rerank request: {body}"))
        .iter()
        .map(|document| document.as_str().expect("a document's text").to_owned())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The owner's bearer and binding headers: a full slip of the owner's own,
/// held by the owner's key, as the served recall reads under the presented
/// slip for the actor it binds (FIX RECALL-HOST-ROOT-READ-REFUSED).
fn owner_auth(vault: &Vault, issuer: &HostSlipIssuer) -> (String, String) {
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("device-only rerank owner actor");
    let root = vault
        .ensure_host_root_slip(issuer)
        .expect("device-only rerank host root slip");
    let holder_key = SigningKey::from_bytes(&[0x53; 32]);
    let mut claims = root.claims.clone();
    claims.slip_id = [0x53; 32];
    claims.parent_id = None;
    claims.holder_ref = owner.to_hex();
    claims.binding_key = holder_key.verifying_key().to_bytes();
    claims.actor_class = Some("human".to_owned());
    claims.scope = Scope::top();
    let slip = vault
        .mint_capability_slip(issuer, claims)
        .expect("device-only rerank owner slip");
    let timestamp = vault.now_recorded_at();
    let nonce = EntityId::now().to_hex();
    let challenge = holder_proof_challenge(timestamp, &nonce);
    let transcript = slip
        .binding_transcript(&challenge)
        .expect("device-only rerank owner transcript");
    let proof = holder_key.sign(&transcript).to_bytes();
    let bearer = slip.to_token().expect("device-only rerank owner token");
    let binding =
        json!({"timestamp": timestamp, "nonce": nonce, "signature": hex(&proof)}).to_string();
    (format!("Bearer {bearer}"), binding)
}

/// An auto claim of `text` about `subject` in `world` (base reality for
/// `None`), indexed by its words.
fn remember(vault: &Vault, subject: EntityId, world: Option<EntityId>, text: &str) {
    let mut body = ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        rmpv::Value::from(text),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("device-only rerank claim body");
    body.world = world;
    let id = EntityId::now();
    vault
        .put_claim(&id, &body, TimeRange { start: 10, end: 10 }, 10)
        .expect("device-only rerank claim");
    vault
        .batch()
        .text(&id, &[("body", text)])
        .commit()
        .expect("device-only rerank text index");
}

/// A WORLD the owner keeps on this machine, holding [`KEPT`], and
/// [`PORTABLE`] in base reality, both indexed; answers the world.
fn seed(vault: &Vault, issuer: &HostSlipIssuer) -> EntityId {
    let world = EntityId::now();
    vault
        .put_entity(
            &world,
            ENTITY_TYPE_WORLD,
            TimeRange { start: 1, end: 1 },
            1,
            b"device-only rerank world",
        )
        .expect("device-only rerank world row");
    let subject = EntityId::now();
    vault
        .put_entity(
            &subject,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"device-only rerank subject",
        )
        .expect("device-only rerank subject row");
    remember(vault, subject, Some(world), KEPT);
    remember(vault, subject, None, PORTABLE);
    vault
        .set_indexed_idle_delay_ms(0)
        .expect("device-only rerank index delay");
    let published = vault
        .refresh_staged_indexed_at_idle(u64::MAX)
        .expect("device-only rerank index refresh");
    assert!(
        published.failed.is_empty(),
        "FIXTURE: the seeded rows are indexed: {:?}",
        published.failed
    );
    vault
        .keep_world_on_this_machine_under_for_test(issuer, world, true)
        .expect("FIXTURE: the owner keeps the world on this machine");
    world
}

/// What one recall at high answered: its HTTP status and body.
struct Recalled {
    status: StatusCode,
    body: Value,
}

impl Recalled {
    /// The answer's items' words, in their answered order.
    fn item_texts(&self) -> Vec<String> {
        self.body["items"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or(&[])
            .iter()
            .filter_map(|item| item["value_text"].as_str().map(str::to_owned))
            .collect()
    }

    fn rerank_status(&self) -> &Value {
        &self.body["retrieval_meta"]["rerank"]["status"]
    }
}

/// A fresh vault served on `models`, its kept and portable claims seeded,
/// recalled once at high as its owner, from this device. With `socket`, the
/// stub on `<socket dir>/stub.sock` (logging to `<socket dir>/stub.log`) is
/// recorded as the `listen = "unix"` row's launch first.
async fn recall_kept(models: &ModelsConfig, socket: Option<&Path>) -> Recalled {
    // This process launches managed workers, as plain serve does, before it
    // builds its models: the socket reranker's routes are captured then.
    permit_worker_launch();
    let dir = tempfile::tempdir().expect("device-only rerank vault dir");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = SyncServer::new(
        Arc::clone(&vault),
        SyncServerConfig {
            auth_secret: Some(AUTH_SECRET.to_owned()),
            ..Default::default()
        },
    )
    .expect("device-only rerank server");
    let (server, host) = AiHost::attach(server, Some(models)).await;
    let stub = match socket {
        Some(socket_dir) => {
            let socket = socket_dir.join("stub.sock");
            let stub = start_stub(&socket, &socket_dir.join("stub.log")).await;
            assert!(
                record_socket_launch(WORKER, &socket, &stub),
                "FIXTURE: the hosted listen = \"unix\" row takes the stub as its launch"
            );
            Some(stub)
        }
        None => None,
    };
    let router = build_app(Arc::new(server));
    let issuer = vault
        .load_host_slip_issuer()
        .expect("device-only rerank host issuer");
    let world = seed(&vault, &issuer);
    let auth = owner_auth(&vault, &issuer);
    let mut request = Request::builder()
        .method("POST")
        .uri("/v1/core/facade/vault.recall")
        .header("content-type", "application/json")
        .header("authorization", auth.0.as_str())
        .header("x-oneiron-binding", auth.1.as_str())
        .body(Body::from(
            json!({
                "query": QUERY,
                "effort": "high",
                "limit": 10,
                "scope": {
                    "worlds": {
                        "kind": "world",
                        "world_ref": world.to_hex(),
                        "include_base": true,
                    },
                },
            })
            .to_string(),
        ))
        .expect("device-only rerank request");
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40101))));
    let response = router.oneshot(request).await.expect("recall response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("recall body");
    let body: Value = serde_json::from_slice(&bytes).expect("recall json body");
    host.shutdown().await;
    if let Some(stub) = stub {
        stub.stop().await;
    }
    Recalled { status, body }
}

/// Head: the reranker's one rung is the socket worker, so its on-device view
/// serves every rung of the seat. The recall sends the kept claim's words on
/// the socket, the stub scores it by the query's words, and it ranks first.
/// On main the kept claim goes empty and ranks last.
#[test]
fn kept_rows_are_reranked_with_their_words_on_a_socket_reranker() {
    let _turn = HOST_TURN.lock().unwrap_or_else(PoisonError::into_inner);
    run_on_engine_stack("device-only-rerank-socket", || async {
        let dir = tempfile::tempdir().expect("models dir");
        let models = socket_models(
            dir.path(),
            r#"{ model = "house-rerank:stub-reranker" }"#,
            "",
        );
        let recalled = recall_kept(&models, Some(dir.path())).await;
        assert_eq!(recalled.status, StatusCode::OK, "{}", recalled.body);

        let posts = stub_rerank_bodies(&dir.path().join("stub.log"));
        assert_eq!(
            posts.len(),
            1,
            "one rerank call went on the socket: {posts:?}"
        );
        let sent = documents(&posts[0]);
        assert!(
            sent.contains(&document(KEPT)),
            "the kept claim's words reach the reranker on this device: {sent:?}"
        );
        assert!(
            sent.contains(&document(PORTABLE)),
            "FIXTURE: the portable claim is in the block: {sent:?}"
        );
        assert_eq!(
            recalled.rerank_status(),
            "applied",
            "the block is in the reranker's order: {}",
            recalled.body
        );
        let texts = recalled.item_texts();
        assert_eq!(
            texts.first().map(String::as_str),
            Some(KEPT),
            "the kept claim holds every word of the query and ranks first: {texts:?}"
        );
    });
}

/// Control (main and head): a reranker over loopback HTTP does not run on
/// the device (I2-LOCAL: a loopback address alone is not the trust
/// contract), so the recall sends it the kept claim empty.
#[test]
fn a_loopback_http_reranker_is_sent_a_kept_row_empty() {
    let _turn = HOST_TURN.lock().unwrap_or_else(PoisonError::into_inner);
    run_on_engine_stack("device-only-rerank-http", || async {
        let fake = FakeReranker::start().await;
        let recalled = recall_kept(&http_models(&fake.base_url), None).await;
        assert_eq!(recalled.status, StatusCode::OK, "{}", recalled.body);
        let seen = fake.seen();
        assert_eq!(seen.len(), 1, "one rerank call went over HTTP: {seen:?}");
        let sent = documents(&seen[0]);
        assert!(
            !sent.contains(&document(KEPT)),
            "the kept claim's words never leave over HTTP: {sent:?}"
        );
        assert!(
            sent.iter().any(String::is_empty),
            "the kept claim goes empty: {sent:?}"
        );
        assert!(
            sent.contains(&document(PORTABLE)),
            "FIXTURE: the portable claim is in the block: {sent:?}"
        );
    });
}

/// Control (main and head): a seat whose socket rung has an HTTP rung
/// behind it could fall back off the device, and its on-device view drops
/// that rung, so the recall does not run on the device: the socket stub,
/// which answers first, is sent the kept claim empty.
#[test]
fn a_seat_with_an_http_rung_behind_its_socket_rung_sends_a_kept_row_empty() {
    let _turn = HOST_TURN.lock().unwrap_or_else(PoisonError::into_inner);
    run_on_engine_stack("device-only-rerank-mixed", || async {
        let fake = FakeReranker::start().await;
        let dir = tempfile::tempdir().expect("models dir");
        let models = socket_models(
            dir.path(),
            r#"{ model = "house-rerank:stub-reranker" }, { model = "loopback:fake-reranker" }"#,
            &format!(
                "\n[providers.loopback]\nkind = \"local-openai-compat\"\nbase_url = \"{}\"\nrevision = \"v1\"\n",
                fake.base_url
            ),
        );
        let recalled = recall_kept(&models, Some(dir.path())).await;
        assert_eq!(recalled.status, StatusCode::OK, "{}", recalled.body);

        let posts = stub_rerank_bodies(&dir.path().join("stub.log"));
        assert_eq!(
            posts.len(),
            1,
            "the socket rung answers the one rerank call: {posts:?}"
        );
        assert_eq!(fake.calls(), 0, "the HTTP rung behind it is not called");
        let sent = documents(&posts[0]);
        assert!(
            !sent.contains(&document(KEPT)),
            "a seat that can fall back off the device is sent no kept words: {sent:?}"
        );
        assert!(
            sent.iter().any(String::is_empty),
            "the kept claim goes empty: {sent:?}"
        );
        assert!(
            sent.contains(&document(PORTABLE)),
            "FIXTURE: the portable claim is in the block: {sent:?}"
        );
    });
}
