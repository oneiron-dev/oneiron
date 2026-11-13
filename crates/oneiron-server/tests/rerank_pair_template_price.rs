//! L9-14 (ARCH-0004 `#rerank-door-open`): a paid recall's rerank call is
//! priced before it leaves at its words and at what the reranker's template
//! adds to each query and document pair, `[models.recall]
//! rerank_pair_template_units`. Unset, a pair costs its words and 16, a
//! cross-encoder's marks, as before.
//!
//! Each case recalls at high through `POST /v1/core/facade/vault.recall` as
//! the owner, on a loopback `/v1/rerank`. A probe recall on a vault of the
//! same rows, on the default line, reads what the recall sends (its bytes
//! `B` and its pairs `n`). Then a line one unit short of the price refuses
//! the call unsent with `BUDGET_SPENT`, and a line of exactly the price
//! sends it once.

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::{ConnectInfo, State};
use axum::{
    Json, Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use engine_stack::run_on_engine_stack;
use oneiron::authority::HostSlipIssuer;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EntityId, TimeRange,
    Vault, VaultConfig,
};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::ai_host::AiHost;
use oneiron_server::build_app;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::config::models::ModelsConfig;
use oneiron_server::server::SyncServer;
use serde_json::{Value, json};
use tower::ServiceExt;

// The configured server secret that selects secret-based rooting at boot; it is
// config, not issuer key material. The owner's proof is the keystore issuer the
// server bootstrapped, loaded back through `Vault::load_host_slip_issuer`.
const AUTH_SECRET: &str = "rerank-pair-template-auth-secret";
const QUERY: &str = "lantern repair";
const PASSAGES: [&str; 5] = [
    "the brass lantern in the attic",
    "lantern repair notes for the lantern repair kit",
    "lantern repair: replace the lantern wick",
    "repair the lantern frame before the lantern show",
    "lantern repair shop hours and lantern prices",
];
/// The share an instruction-style reranker's template adds to each pair, far
/// past a cross-encoder's 16 marks.
const TEMPLATE_UNITS: u64 = 400;
/// What a pair costs beside its words with no `rerank_pair_template_units`.
const DEFAULT_PAIR_UNITS: u64 = 16;
/// The line the probe recall runs on: `[models.recall]`'s default.
const PROBE_LINE: u64 = 32_000;

/// A loopback `/v1/rerank`: each call is kept and counted, every document
/// scores 0.5, and each answer reports 10 tokens used.
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
            .route("/v1/rerank", axum::routing::post(rerank))
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
        self.fake.seen.lock().expect("fake reranker calls").clone()
    }
}

async fn rerank(State(fake): State<Fake>, Json(body): Json<Value>) -> Json<Value> {
    fake.calls.fetch_add(1, Ordering::SeqCst);
    fake.seen.lock().expect("fake reranker calls").push(body.clone());
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

/// `[models]` routing the reranker to `base_url` on a line of `line` units,
/// with `[models.recall] rerank_pair_template_units = template` when given.
fn models(base_url: &str, line: u64, template: Option<u64>) -> ModelsConfig {
    let template = template.map_or_else(String::new, |units| {
        format!("rerank_pair_template_units = {units}\n")
    });
    let toml = format!(
        "[providers.rerank]\n\
         kind = \"local-openai-compat\"\n\
         base_url = \"{base_url}\"\n\
         [roles.reranker]\n\
         model = \"rerank:fake-reranker\"\n\
         [dreamer]\n\
         enabled = false\n\
         [recall]\n\
         rerank_budget_units = {line}\n\
         {template}"
    );
    ModelsConfig::from_toml(&toml, None).unwrap_or_else(|error| {
        panic!("[models.recall] takes the reranker's pair template share: {error:#}")
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn owner_auth(vault: &Vault, issuer: &HostSlipIssuer) -> (String, String) {
    let slip = vault
        .ensure_host_root_slip(issuer)
        .expect("rerank template host root slip");
    let timestamp = vault.now_recorded_at();
    let nonce = EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let proof = issuer
        .binding_proof(&slip, challenge.as_bytes())
        .expect("rerank template owner proof");
    let bearer = slip.to_token().expect("rerank template owner token");
    let binding =
        json!({"timestamp": timestamp, "nonce": nonce, "signature": hex(&proof)}).to_string();
    (format!("Bearer {bearer}"), binding)
}

/// Each of [`PASSAGES`] as an auto claim about one person, indexed.
fn seed(vault: &Vault) {
    let subject = EntityId::now();
    vault
        .put_entity(
            &subject,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"rerank template subject",
        )
        .expect("rerank template subject row");
    for text in PASSAGES {
        let body = ClaimBody::new(
            "profile.note",
            ClaimSubject::Entity(subject),
            rmpv::Value::from(text),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )
        .expect("rerank template claim body");
        let id = EntityId::now();
        vault
            .put_claim(&id, &body, TimeRange { start: 10, end: 10 }, 10)
            .expect("rerank template claim");
        vault
            .batch()
            .text(&id, &[("body", text)])
            .commit()
            .expect("rerank template text index");
    }
    vault
        .set_indexed_idle_delay_ms(0)
        .expect("rerank template index delay");
    let published = vault
        .refresh_staged_indexed_at_idle(u64::MAX)
        .expect("rerank template index refresh");
    assert!(
        published.failed.is_empty(),
        "FIXTURE: the seeded rows are indexed: {:?}",
        published.failed
    );
}

/// What one recall at high answered: its HTTP status and body.
struct Recalled {
    status: StatusCode,
    body: Value,
}

/// A fresh vault of [`PASSAGES`] served on `models`, recalled once at high
/// as its owner, from this device.
async fn recall_high(models: &ModelsConfig) -> Recalled {
    let dir = tempfile::tempdir().expect("rerank template dir");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = SyncServer::new(
        Arc::clone(&vault),
        SyncServerConfig {
            auth_secret: Some(AUTH_SECRET.to_owned()),
            ..Default::default()
        },
    )
    .expect("rerank template server");
    let (server, host) = AiHost::attach(server, Some(models)).await;
    let router = build_app(Arc::new(server));
    seed(&vault);
    let issuer = vault
        .load_host_slip_issuer()
        .expect("rerank template host issuer");
    let auth = owner_auth(&vault, &issuer);
    let mut request = Request::builder()
        .method("POST")
        .uri("/v1/core/facade/vault.recall")
        .header("content-type", "application/json")
        .header("authorization", auth.0.as_str())
        .header("x-oneiron-binding", auth.1.as_str())
        .body(Body::from(
            json!({"query": QUERY, "effort": "high", "limit": 10}).to_string(),
        ))
        .expect("rerank template request");
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40100))));
    let response = router.oneshot(request).await.expect("recall response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("recall body");
    let body: Value = serde_json::from_slice(&bytes).expect("recall json body");
    host.shutdown().await;
    Recalled { status, body }
}

/// What the recall of [`PASSAGES`] sends its reranker, read on the default
/// line: the documents, and the bytes a pair's words price at in all (the
/// query once beside each document).
struct Payload {
    documents: Vec<String>,
    word_units: u64,
}

impl Payload {
    fn pairs(&self) -> u64 {
        u64::try_from(self.documents.len()).expect("pair count")
    }

    /// The price of the call at `per_pair` units a pair beside its words.
    fn price(&self, per_pair: u64) -> u64 {
        self.word_units + self.pairs() * per_pair
    }
}

fn sent_documents(seen: &Value) -> Vec<String> {
    let mut documents: Vec<String> = seen["documents"]
        .as_array()
        .unwrap_or_else(|| panic!("a rerank request: {seen}"))
        .iter()
        .map(|document| document.as_str().expect("a document's text").to_owned())
        .collect();
    documents.sort();
    documents
}

async fn probe() -> Payload {
    let fake = FakeReranker::start().await;
    let recalled = recall_high(&models(&fake.base_url, PROBE_LINE, None)).await;
    assert_eq!(
        recalled.status,
        StatusCode::OK,
        "FIXTURE: the probe recall reranks on the default line: {}",
        recalled.body
    );
    let seen = fake.seen();
    assert_eq!(seen.len(), 1, "FIXTURE: the probe recall calls the reranker once");
    assert_eq!(seen[0]["query"], QUERY, "FIXTURE: the reranker reads the query");
    let documents = sent_documents(&seen[0]);
    assert!(
        documents.len() >= 2,
        "FIXTURE: the recall reranks a block of the seeded passages: {documents:?}"
    );
    let query = u64::try_from(QUERY.len()).expect("query bytes");
    let word_units = documents
        .iter()
        .map(|document| query + u64::try_from(document.len()).expect("document bytes"))
        .sum();
    Payload {
        documents,
        word_units,
    }
}

/// One recall at high on `line` and `template`: it is refused unsent as
/// `BUDGET_SPENT`.
async fn assert_refused_unsent(line: u64, template: Option<u64>, why: &str) {
    let fake = FakeReranker::start().await;
    let recalled = recall_high(&models(&fake.base_url, line, template)).await;
    assert_ne!(recalled.status, StatusCode::OK, "{why}: {}", recalled.body);
    assert_eq!(
        recalled.body["error"]["code"], "BUDGET_SPENT",
        "{why}: {}",
        recalled.body
    );
    assert_eq!(fake.calls(), 0, "{why}: nothing was sent");
}

/// One recall at high on `line` and `template`: it reranks with one call
/// that sends the probe's documents.
async fn assert_sent_once(payload: &Payload, line: u64, template: Option<u64>, why: &str) {
    let fake = FakeReranker::start().await;
    let recalled = recall_high(&models(&fake.base_url, line, template)).await;
    assert_eq!(recalled.status, StatusCode::OK, "{why}: {}", recalled.body);
    let seen = fake.seen();
    assert_eq!(seen.len(), 1, "{why}: one rerank call went out");
    assert_eq!(
        sent_documents(&seen[0]),
        payload.documents,
        "FIXTURE: each vault's recall sends the probe's documents"
    );
}

/// Head: with `rerank_pair_template_units` set, each pair is priced at its
/// words and the template's share. A line that covers the words and a
/// cross-encoder's 16 marks a pair, one unit short of the template's price,
/// refuses the call unsent; a line of the price sends it.
#[test]
fn a_pair_template_is_priced_into_each_pair_before_the_call_leaves() {
    run_on_engine_stack("rerank-pair-template", || async {
        let payload = probe().await;
        let price = payload.price(TEMPLATE_UNITS);
        assert!(
            price > payload.price(DEFAULT_PAIR_UNITS),
            "FIXTURE: the short line covers the words and a cross-encoder's marks"
        );
        assert_refused_unsent(
            price - 1,
            Some(TEMPLATE_UNITS),
            "a line one unit short of the words and the template's share a pair",
        )
        .await;
        assert_sent_once(
            &payload,
            price,
            Some(TEMPLATE_UNITS),
            "a line of the words and the template's share a pair",
        )
        .await;
    });
}

/// Control (main and head): with no `rerank_pair_template_units`, a pair
/// is priced at its words and 16, as before. A line one unit short refuses
/// the call unsent; a line of that price sends it.
#[test]
fn without_a_pair_template_each_pair_is_priced_at_its_words_and_sixteen() {
    run_on_engine_stack("rerank-pair-default", || async {
        let payload = probe().await;
        let price = payload.price(DEFAULT_PAIR_UNITS);
        assert_refused_unsent(
            price - 1,
            None,
            "a line one unit short of the words and 16 a pair",
        )
        .await;
        assert_sent_once(&payload, price, None, "a line of the words and 16 a pair").await;
    });
}
