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
//! - Review round 1: a manifest's on-device pin of the socket reranker's
//!   model reaches it by its own id and is sent the kept claim's words; a
//!   view as long as its seat but holding a rung the seat's `leave_device`
//!   refused is no on-device route; a kept world whose model order leaves no
//!   rung of the on-device route has its block built as for a host off the
//!   device, scored on the ordinary route with the kept claim empty. Red at
//!   the round-1 head cda7e17a5b30: the pin is refused, the view is taken,
//!   the call is refused.
//! - Review round 2: with the world made portable, a model order that
//!   leaves no rung of a local-GPU model pack's on-device pick, or drops on
//!   the device a rung the ordinary route takes (a night rung outside its
//!   hours beside the stub), has its block scored on the ordinary route, as
//!   on main: the pack's pick takes its own-server rung, the seat its stub
//!   rung. Red at the round-1 head f1a1172169c8: nothing is sent.
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

use std::collections::BTreeMap;
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
use oneiron::authority::{
    ActSurface, HostSlipIssuer, ModelOrder, ReadLocation, SealedCopies, WorldPrivacy,
    holder_proof_challenge,
};
use oneiron::federation::Scope;
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_WORLD};
use oneiron::store::GateDecisionId;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EntityId, ModelId,
    ModelLocality, ModelTierRef, TimeRange, Vault, VaultConfig,
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

/// The socket rung's engine model id, which a manifest pins.
const STUB_MODEL: &str = "house-rerank/stub-reranker@v1";
/// The socket rung's ordinary offer (its provider's origin), not its
/// on-device one.
// testkit-lint: allow(fixed-port) a route name in a world's model order: nothing binds or calls it
const STUB_ORDINARY_OFFER: &str = "house-rerank/stub-reranker@v1@127.0.0.1:18433";

/// `[models]` whose `[roles.reranker]` table is `role`, beside the
/// `house-rerank` provider served by a managed llama.cpp worker on its own
/// socket for the reranker alone, and `extra` providers and rows.
fn socket_models(dir: &Path, role: &str, extra: &str) -> ModelsConfig {
    let toml = format!(
        r#"
[providers.house-rerank]
kind = "local-openai-compat"
base_url = "http://127.0.0.1:18433" # testkit-lint: allow(fixed-port) config text: nothing binds or calls a provider its socket rows serve
revision = "v1"
timeout_secs = 20
{extra}
[roles.reranker]
{role}
{row}
[dreamer]
enabled = false
"#,
        row = socket_row(dir, WORKER, "house-rerank:stub-reranker"),
    );
    ModelsConfig::from_toml(&toml, None)
        .unwrap_or_else(|error| panic!("FIXTURE: a listen = \"unix\" reranker row: {error:#}"))
}

/// A managed llama.cpp worker row `id` serving `model` on a Unix socket of
/// its own. Nothing is installed: its artifacts are paths under `dir` that
/// do not exist, so its supervisor never launches, and the test door records
/// the stub as its launch instead.
fn socket_row(dir: &Path, id: &str, model: &str) -> String {
    format!(
        "\n[workers.{id}]\nmodel = \"{model}\"\nkind = \"llama_cpp\"\nmode = \"managed\"\n\
         listen = \"unix\"\nweights_manifest = \"{}\"\nserver = \"{}\"\nserver_sha256 = \"{}\"\n\
         runtime_root = \"{}\"\n",
        dir.join("absent-weights.json").display(),
        dir.join("absent-server-binary").display(),
        "0".repeat(64),
        dir.join("rt").display(),
    )
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
/// `policy` set on it and the kept world, recalled once at high as its
/// owner, from this device. With `socket`, the stub on
/// `<socket dir>/stub.sock` (logging to `<socket dir>/stub.log`) is recorded
/// as the `listen = "unix"` row's launch first.
async fn recall_kept(
    models: &ModelsConfig,
    socket: Option<&Path>,
    policy: fn(&Vault, EntityId),
) -> Recalled {
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
    policy(&vault, world);
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

/// The vault's model policy as the seed leaves it: no manifest, every
/// world's model order inherited.
fn seeded_policy(_vault: &Vault, _world: EntityId) {}

/// The owner, authenticated on this install.
fn owner(vault: &Vault) -> oneiron::consent::AuthenticatedOwner {
    let person = vault.ensure_embedded_owner_actor().expect("embedded owner");
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("FIXTURE: the authenticated owner")
}

/// A model manifest pinning every role to [`STUB_MODEL`] on the LLM slot
/// routed on this device (the extraction encoder to its encoder id on the
/// Oneironer slot), its teacher probe-approved, as an owner pins one.
fn pin_stub_on_device(vault: &Vault, _world: EntityId) {
    use oneiron::llm::manifest::{
        MODEL_ROLES, ModelBinding, ModelManifest, ModelRole, ModelSlot, TeacherProbeApproval,
    };
    let model = ModelId::new(STUB_MODEL).expect("model id");
    let encoder = ModelId::new("house-rerank/stub-reranker-encoder@v1").expect("encoder id");
    let binding = |model: &ModelId, slot| ModelBinding {
        model: model.clone(),
        slot,
        tier: ModelTierRef("pinned".into()),
        route_models: BTreeMap::new(),
        disposition: None,
        reads_audio: false,
    };
    let manifest = ModelManifest {
        version: 2,
        roles: MODEL_ROLES
            .into_iter()
            .map(|role| match role {
                ModelRole::ExtractionEncoder => (role, binding(&encoder, ModelSlot::Oneironer)),
                _ => (role, binding(&model, ModelSlot::Llm)),
            })
            .collect(),
        routes: [ModelSlot::Llm, ModelSlot::Embedder, ModelSlot::Oneironer]
            .into_iter()
            .map(|slot| (slot, ModelLocality::OnDevice))
            .collect(),
        verdict: None,
        seat_policy: None,
    };
    let policy = vault
        .teacher_probe_policy(None)
        .expect("teacher probe policy");
    let approval = TeacherProbeApproval::for_scored_checkpoint(&manifest, &policy, 1_000_000)
        .expect("teacher probe approval");
    vault
        .set_model_manifest_with_teacher_approval(&manifest, &approval)
        .expect("FIXTURE: the owner's on-device model manifest");
}

/// The kept world, still kept on this machine, with a model order naming
/// only the socket rung's ordinary offer ([`STUB_ORDINARY_OFFER`]).
fn order_kept_world(vault: &Vault, world: EntityId) {
    let machine = vault
        .local_machine()
        .expect("local machine")
        .expect("FIXTURE: keeping the world enrolled this install")
        .id;
    let privacy = WorldPrivacy {
        read: ReadLocation::OneMachine(machine),
        models: ModelOrder::Ordered(vec![STUB_ORDINARY_OFFER.to_owned()]),
        ..WorldPrivacy::default()
    };
    vault
        .set_world_privacy_as(&owner(vault), ActSurface::ThisInstall, world, privacy, None)
        .expect("FIXTURE: the owner orders the kept world's models");
}

/// The one rerank request the socket stub of `dir` was sent, read as the
/// block of a host off the device: the kept claim empty, the portable claim
/// with its words.
fn assert_kept_row_sent_empty(dir: &Path) {
    let posts = stub_rerank_bodies(&dir.join("stub.log"));
    assert_eq!(
        posts.len(),
        1,
        "one rerank call went on the socket: {posts:?}"
    );
    let sent = documents(&posts[0]);
    assert!(
        !sent.contains(&document(KEPT)),
        "the kept claim's words are not sent: {sent:?}"
    );
    assert!(
        sent.iter().any(String::is_empty),
        "the kept claim goes empty: {sent:?}"
    );
    assert!(
        sent.contains(&document(PORTABLE)),
        "FIXTURE: the portable claim is in the block: {sent:?}"
    );
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
        let models = socket_models(dir.path(), ONE_SOCKET_RUNG, "");
        let recalled = recall_kept(&models, Some(dir.path()), seeded_policy).await;
        assert_eq!(recalled.status, StatusCode::OK, "{}", recalled.body);
        assert_kept_row_reranked_first(dir.path(), &recalled);
    });
}

/// The socket stub of `dir` was sent the kept claim's words in one call, and
/// the recall ranks the kept claim first, in the stub's order.
fn assert_kept_row_reranked_first(dir: &Path, recalled: &Recalled) {
    let posts = stub_rerank_bodies(&dir.join("stub.log"));
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
}

/// Control (main and head): a reranker over loopback HTTP does not run on
/// the device (I2-LOCAL: a loopback address alone is not the trust
/// contract), so the recall sends it the kept claim empty.
#[test]
fn a_loopback_http_reranker_is_sent_a_kept_row_empty() {
    let _turn = HOST_TURN.lock().unwrap_or_else(PoisonError::into_inner);
    run_on_engine_stack("device-only-rerank-http", || async {
        let fake = FakeReranker::start().await;
        let recalled = recall_kept(&http_models(&fake.base_url), None, seeded_policy).await;
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
            r#"rungs = [{ model = "house-rerank:stub-reranker" }, { model = "loopback:fake-reranker" }]"#,
            &loopback_provider(&fake.base_url),
        );
        let recalled = recall_kept(&models, Some(dir.path()), seeded_policy).await;
        assert_eq!(recalled.status, StatusCode::OK, "{}", recalled.body);
        assert_kept_row_sent_empty(dir.path());
        assert_eq!(fake.calls(), 0, "the HTTP rung behind it is not called");
    });
}

/// The reranker's one rung: the socket worker.
const ONE_SOCKET_RUNG: &str = r#"rungs = [{ model = "house-rerank:stub-reranker" }]"#;

/// The `loopback` provider, reached over HTTP at `base_url`.
fn loopback_provider(base_url: &str) -> String {
    format!(
        "\n[providers.loopback]\nkind = \"local-openai-compat\"\nbase_url = \"{base_url}\"\nrevision = \"v1\"\n"
    )
}

/// Review round 1, P1 1: a manifest pins the socket rung's model by its own
/// id at the on-device route. Its route is that model's on-device offer, the
/// socket alone, so the recall sends the kept claim's words on it. Red at
/// cda7e17a5b30: no on-device offer is known by that id, the pin is refused
/// and nothing is sent.
#[test]
fn a_manifest_pin_on_device_of_the_socket_model_is_sent_kept_words() {
    let _turn = HOST_TURN.lock().unwrap_or_else(PoisonError::into_inner);
    run_on_engine_stack("device-only-rerank-manifest", || async {
        let dir = tempfile::tempdir().expect("models dir");
        let models = socket_models(dir.path(), ONE_SOCKET_RUNG, "");
        let recalled = recall_kept(&models, Some(dir.path()), pin_stub_on_device).await;
        assert_eq!(recalled.status, StatusCode::OK, "{}", recalled.body);
        assert_kept_row_reranked_first(dir.path(), &recalled);
    });
}

/// Review round 1, P1 2: under `leave_device = "never"` the seat drops a
/// socket rung whose provider is third-party, while its on-device view keeps
/// it and has no rung for the HTTP rung: seat [socket, HTTP], view [socket,
/// third-party socket], as many rungs each. The view is not the seat, so the
/// socket stub is sent the kept claim empty and the HTTP rung is not called.
/// Red at cda7e17a5b30: equal counts took the view.
#[test]
fn a_view_holding_a_rung_the_seat_refused_sends_a_kept_row_empty() {
    let _turn = HOST_TURN.lock().unwrap_or_else(PoisonError::into_inner);
    run_on_engine_stack("device-only-rerank-refused-rung", || async {
        let fake = FakeReranker::start().await;
        let dir = tempfile::tempdir().expect("models dir");
        let paid = format!(
            r#"
[providers.paid-rerank]
kind = "local-openai-compat"
base_url = "http://127.0.0.1:18434" # testkit-lint: allow(fixed-port) config text: nothing binds or calls a provider its socket rows serve
revision = "v1"
locality = "third_party"
{row}{loopback}"#,
            row = socket_row(
                &dir.path().join("paid"),
                "paid-socket",
                "paid-rerank:stub-reranker"
            ),
            loopback = loopback_provider(&fake.base_url),
        );
        let models = socket_models(
            dir.path(),
            r#"rungs = [{ model = "house-rerank:stub-reranker" }, { model = "paid-rerank:stub-reranker" }, { model = "loopback:fake-reranker" }]
leave_device = "never""#,
            &paid,
        );
        let recalled = recall_kept(&models, Some(dir.path()), seeded_policy).await;
        assert_eq!(recalled.status, StatusCode::OK, "{}", recalled.body);
        assert_kept_row_sent_empty(dir.path());
        assert_eq!(fake.calls(), 0, "the HTTP rung behind it is not called");
    });
}

/// Review round 1, P1 3: the kept world's model order names only the socket
/// rung's ordinary offer, so the on-device route has no rung for a block
/// that carries the kept claim's words. The block is built as for a host off
/// the device: the kept claim goes empty, and the call takes the ordinary
/// route, which the order of the rows sent with words (base reality alone)
/// leaves. Red at cda7e17a5b30: the on-device call is refused, nothing is
/// sent and the recall fails.
#[test]
fn a_kept_world_ordering_no_on_device_rung_sends_its_row_empty() {
    let _turn = HOST_TURN.lock().unwrap_or_else(PoisonError::into_inner);
    run_on_engine_stack("device-only-rerank-world-order", || async {
        let dir = tempfile::tempdir().expect("models dir");
        let models = socket_models(dir.path(), ONE_SOCKET_RUNG, "");
        let recalled = recall_kept(&models, Some(dir.path()), order_kept_world).await;
        assert_eq!(recalled.status, StatusCode::OK, "{}", recalled.body);
        assert_kept_row_sent_empty(dir.path());
    });
}

/// The world read everywhere, no longer kept on this machine, with a model
/// order naming `offers` alone: its claim is sent with its words wherever
/// the reranker runs, and its order picks the call's rungs.
fn order_world_portable(vault: &Vault, world: EntityId, offers: &[&str]) {
    let privacy = WorldPrivacy {
        read: ReadLocation::Everywhere,
        sealed: SealedCopies::Off,
        models: ModelOrder::Ordered(offers.iter().map(|offer| (*offer).to_owned()).collect()),
    };
    vault
        .set_world_privacy_as(&owner(vault), ActSurface::ThisInstall, world, privacy, None)
        .expect("FIXTURE: the owner makes the world portable and orders its models");
}

/// The socket stub of `dir` was sent both claims with their words in one
/// call, and the recall ranks the world's claim, which holds every word of
/// the query, first, in the stub's order.
fn assert_both_rows_reranked(dir: &Path, recalled: &Recalled) {
    let posts = stub_rerank_bodies(&dir.join("stub.log"));
    assert_eq!(
        posts.len(),
        1,
        "one rerank call went on the socket: {posts:?}"
    );
    let sent = documents(&posts[0]);
    assert!(
        sent.contains(&document(KEPT)) && sent.contains(&document(PORTABLE)),
        "the portable world's claim and base reality's are sent with their words: {sent:?}"
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
        "the claim holding every word of the query ranks first: {texts:?}"
    );
}

/// A local-GPU model pack, the vault's pinned pack, picking [`STUB_MODEL`]
/// for the reranker, and the world made portable with a model order naming
/// only the socket rung's ordinary offer ([`STUB_ORDINARY_OFFER`]).
fn pick_stub_by_pack_and_order_world(vault: &Vault, world: EntityId) {
    use oneiron::skill_hub::HubFile;
    use oneiron::skill_hub::pack_catalog::{PackInstallDisposition, PackInstallStatus};
    let name = "fixture.device-only-rerank";
    let document = json!({
        "format": 1,
        "season": "device-only-rerank",
        "released_epoch_day": 0,
        "roles": {
            "reranker": [{
                "access": {"kind": "local_gpu"},
                "model": STUB_MODEL,
                "when": "The reranker runs on this install's socket worker."
            }]
        }
    });
    let proof = oneiron::test_doors::steward::owner(vault).expect("FIXTURE: the owner's proof");
    let installed = vault
        .put_pack(
            &proof,
            vec![
                HubFile::new(
                    "PACK.md",
                    format!(
                        "---\nname: {name}\ndescription: Local reranker route fixture.\n\
                         version: 1.0.0\nkind: model\n---\nData-only test model pack.\n"
                    ),
                ),
                HubFile::new("knowledge/model-pack.json", document.to_string()),
            ],
        )
        .expect("FIXTURE: the model pack installs");
    let PackInstallDisposition::Installed(receipt) = installed else {
        panic!("FIXTURE: the data-only model pack installs, found {installed:?}");
    };
    assert_eq!(
        receipt.status,
        PackInstallStatus::Active,
        "FIXTURE: the owner installs the reranker model pack active"
    );
    let person = vault.ensure_embedded_owner_actor().expect("embedded owner");
    oneiron::verbs::invoke(
        &vault.memory(person, oneiron::EdgeActorClass::Human),
        "vault.settings.set",
        json!({
            "key": "models.pack_preference",
            "scope": {"kind": "vault"},
            "value": {"mode": "pinned_pack", "pack": name},
        }),
    )
    .unwrap_or_else(|error| panic!("FIXTURE: the owner pins the reranker model pack: {error}"));
    order_world_portable(vault, world, &[STUB_ORDINARY_OFFER]);
}

/// Review round 2, P1 1: a local-GPU model pack picks the socket rung's
/// model for the reranker, so the recall host runs on the device, on that
/// model's on-device view. The portable world's model order names only the
/// rung's ordinary offer, which that view does not hold, so the block is
/// built as for a host off the device, and its call takes the pick's
/// own-server rung, which the order names, as on main. Red at
/// f1a1172169c8: the ordinary route took the on-device view again, the
/// order left it no rung, and nothing was sent.
#[test]
fn a_local_gpu_pack_pick_takes_its_own_server_rung_when_the_order_names_it_alone() {
    let _turn = HOST_TURN.lock().unwrap_or_else(PoisonError::into_inner);
    run_on_engine_stack("device-only-rerank-pack-order", || async {
        let dir = tempfile::tempdir().expect("models dir");
        let models = socket_models(dir.path(), ONE_SOCKET_RUNG, "");
        let recalled =
            recall_kept(&models, Some(dir.path()), pick_stub_by_pack_and_order_world).await;
        assert_eq!(recalled.status, StatusCode::OK, "{}", recalled.body);
        assert_both_rows_reranked(dir.path(), &recalled);
    });
}

/// The night socket rung's on-device offer.
const NIGHT_ON_DEVICE_OFFER: &str = "night-rerank/stub-reranker@v1@on_device";

/// A rung's `hours` in UTC that open an hour from now and close an hour
/// after that, so a call now comes outside them.
fn hours_after_now() -> String {
    const MINUTES_PER_DAY: u64 = 24 * 60;
    // testkit-lint: allow(wall-clock) a rung's daily hours are judged on the server's clock: set an hour from now
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock is after 1970")
        .as_secs()
        / 60
        % MINUTES_PER_DAY;
    let clock = |minute: u64| {
        let minute = minute % MINUTES_PER_DAY;
        format!("{:02}:{:02}", minute / 60, minute % 60)
    };
    format!(
        r#"{{ start = "{}", end = "{}", utc_offset = "+00:00" }}"#,
        clock(now + 60),
        clock(now + 120)
    )
}

/// The portable world's model order names the night socket rung's
/// on-device offer and the stub rung's ordinary offer alone.
fn order_world_night_on_device_stub_ordinary(vault: &Vault, world: EntityId) {
    order_world_portable(vault, world, &[NIGHT_ON_DEVICE_OFFER, STUB_ORDINARY_OFFER]);
}

/// Review round 2, P1 2: the seat's two rungs are socket workers, a night
/// rung outside its hours and the stub, so its on-device view holds every
/// rung of the seat and the recall host runs on the device. The portable
/// world's order names the night rung's on-device offer and the stub's
/// ordinary one: on the device it leaves the night rung alone, dropping the
/// stub the ordinary route takes under it, so the block is built as for a
/// host off the device and its call reaches the stub's ordinary rung, as on
/// main. Red at f1a1172169c8: the on-device call passed the night rung for
/// its hours, had no rung left, and nothing was sent.
#[test]
fn an_order_dropping_an_ordinary_rung_on_the_device_takes_the_ordinary_route() {
    let _turn = HOST_TURN.lock().unwrap_or_else(PoisonError::into_inner);
    run_on_engine_stack("device-only-rerank-dropped-rung", || async {
        let dir = tempfile::tempdir().expect("models dir");
        let night = format!(
            r#"
[providers.night-rerank]
kind = "local-openai-compat"
base_url = "http://127.0.0.1:18435" # testkit-lint: allow(fixed-port) config text: nothing binds or calls a provider its socket rows serve
revision = "v1"
{row}"#,
            row = socket_row(
                &dir.path().join("night"),
                "night-socket",
                "night-rerank:stub-reranker"
            ),
        );
        let models = socket_models(
            dir.path(),
            &format!(
                r#"rungs = [{{ model = "night-rerank:stub-reranker", hours = {} }}, {{ model = "house-rerank:stub-reranker" }}]"#,
                hours_after_now()
            ),
            &night,
        );
        let recalled = recall_kept(
            &models,
            Some(dir.path()),
            order_world_night_on_device_stub_ordinary,
        )
        .await;
        assert_eq!(recalled.status, StatusCode::OK, "{}", recalled.body);
        assert_both_rows_reranked(dir.path(), &recalled);
    });
}
