//! L9-12: a reranker whose provider key is a vault secret reranks through
//! the credential broker's rerank shape, on the runtime's same-user broker
//! child (the built `oneiron-broker` binary) and the vault's real custody
//! door, against a local TLS fake provider. The key is a sentinel made fresh
//! for each case, so no binary holds it.
//!
//! - The `key_secret` reranker's seat is built, and one rerank call goes out
//!   once, to `/v1/rerank`, with the key the broker added. Its scores come
//!   back in document order, and its receipt names the broker.
//! - A key the provider echoes, in an answer or in an error, is in no
//!   answer, error, receipt row or log line of this process.
//! - A reply of exactly the broker's whole-reply bound answers; a reply one
//!   byte over it is refused, and no score comes back.
#![cfg(unix)]

use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Once, PoisonError};
use std::time::Duration;

use base64::Engine as _;
use oneiron::llm::BrokerIsolation;
use oneiron::llm::manifest::ModelRole;
use oneiron::llm::run_admission::{MemoryReceipts, RunEvent};
use oneiron::secret_custody::{CustodyTier, SECRET_SCOPE_READ, SecretBinding};
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, CallClass, CallEnvelope, CallPurpose, ContentPart,
    LlmMessage, LlmMessageRole, LlmRequest, LlmResponse, LlmResult, ModelId, ModelLocality,
    ModelTierRef, ResponseFormat, TierPrecedence, Vault, VaultConfig,
};
use oneiron_broker::testing::{FakeProvider, FakeReply};
use oneiron_server::config::models::ModelsConfig;
use oneiron_server::models::{BROKER_EFFECTOR, KeyDoor, ModelRuntime, VaultKeyDoor};
use serde_json::{Value as JsonValue, json};
use zeroize::Zeroizing;

/// The vault secret the provider's key is registered under: the handle.
const HANDLE: &str = "rerank-provider-key";
const QUERY: &str = "which note mentions the harbour";
const DOCUMENTS: [&str; 2] = [
    "a grocery list for the week",
    "a note about the harbour at dawn",
];
/// The fake's scores for [`DOCUMENTS`], by index, out of order on the wire.
const RESULTS: [(u64, f64); 2] = [(1, 0.92), (0, 0.13)];
/// [`RESULTS`] in document order, as the call answers them.
const SCORES: [f32; 2] = [0.13, 0.92];

/// Every line this process logs, at every level, once [`capture_logs`] ran.
static LOGS: Mutex<Vec<u8>> = Mutex::new(Vec::new());
static CAPTURE: Once = Once::new();

struct LogSink;

impl Write for LogSink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        LOGS.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Makes [`LOGS`] this binary's one subscriber, at trace level.
fn capture_logs() {
    CAPTURE.call_once(|| {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(|| LogSink)
            .try_init()
            .expect("the log capture is this binary's only subscriber");
    });
}

fn captured_logs() -> String {
    String::from_utf8_lossy(&LOGS.lock().unwrap_or_else(PoisonError::into_inner)).into_owned()
}

/// A fresh key for one case: made at run time, so neither this binary nor
/// the broker child holds the bytes.
fn sentinel() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    format!("rerank-sentinel-{nanos:x}-{:x}", std::process::id())
}

/// `text` holds `key` neither raw nor base64.
fn assert_no_key(key: &str, text: &str, what: &str) {
    let encoded = base64::engine::general_purpose::STANDARD.encode(key);
    assert!(!text.contains(key), "the key is in {what}: {text}");
    assert!(
        !text.contains(encoded.trim_end_matches('=')),
        "the base64 key is in {what}: {text}"
    );
}

struct CountingDoor {
    door: VaultKeyDoor,
    reads: AtomicUsize,
}

impl KeyDoor for CountingDoor {
    fn check(&self, name: &str) -> anyhow::Result<()> {
        self.door.check(name)
    }

    fn read(&self, name: &str) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.door.read(name)
    }
}

struct Fixture {
    key: String,
    fake: FakeProvider,
    keys: Arc<CountingDoor>,
    receipts: Arc<MemoryReceipts>,
    runtime: ModelRuntime,
    _vault_dir: tempfile::TempDir,
    _files: tempfile::TempDir,
}

/// A runtime whose `paid` provider, its key the vault secret [`HANDLE`],
/// serves the `reranker` seat through the same-user broker child.
fn fixture() -> Fixture {
    capture_logs();
    let key = sentinel();
    let fake = FakeProvider::start(FakeReply::json(401, &json!({})));
    let files = tempfile::tempdir().expect("fixture dir");
    let ca = files.path().join("ca.pem");
    std::fs::write(&ca, fake.ca_pem()).expect("ca");
    let vault_dir = tempfile::tempdir().expect("vault dir");
    let vault = Arc::new(Vault::open(vault_dir.path(), VaultConfig::default()).expect("vault"));
    vault
        .register_test_secret(
            HANDLE,
            key.as_bytes(),
            vec![SecretBinding {
                effector: BROKER_EFFECTOR.to_owned(),
                tier_ceiling: CustodyTier::T0Doored,
                scopes: vec![SECRET_SCOPE_READ.to_owned()],
            }],
            1_700_000_000,
        )
        .expect("register the key");
    let keys = Arc::new(CountingDoor {
        door: VaultKeyDoor::new(vault),
        reads: AtomicUsize::new(0),
    });
    let receipts = Arc::new(MemoryReceipts::default());
    let config = ModelsConfig::from_toml(
        &format!(
            r#"
[providers.paid]
kind = "openai-compat"
base_url = "{origin}"
key_secret = "{HANDLE}"
revision = "v1"
timeout_secs = 20

[roles.reranker]
rungs = [{{ model = "paid:rerank-small" }}]

[broker]
program = "{program}"
extra_roots = ["{ca}"]
"#,
            origin = fake.origin(),
            program = env!("CARGO_BIN_EXE_oneiron-broker"),
            ca = ca.display(),
        ),
        None,
    )
    .expect("models config");
    let door: Arc<dyn KeyDoor> = keys.clone();
    let runtime = ModelRuntime::build_with_keys(
        Some(&config),
        Some(door),
        oneiron::HostingPrivacyPosture::SelfHostLocal,
    )
    .with_receipts(receipts.clone());
    Fixture {
        key,
        fake,
        keys,
        receipts,
        runtime,
        _vault_dir: vault_dir,
        _files: files,
    }
}

/// The provider's rerank answer to [`DOCUMENTS`]: [`RESULTS`] and 7 tokens.
fn rerank_answer() -> JsonValue {
    json!({
        "model": "rerank-small",
        "results": RESULTS
            .iter()
            .map(|(index, score)| json!({"index": index, "relevance_score": score}))
            .collect::<Vec<_>>(),
        "usage": {"total_tokens": 7},
    })
}

fn json_reply(status: u16, body: &JsonValue) -> FakeReply {
    FakeReply::json(status, body)
}

/// [`rerank_answer`] padded to exactly `len` bytes.
fn padded_answer(len: usize) -> FakeReply {
    let mut answer = rerank_answer();
    answer["pad"] = json!("");
    let unpadded = answer.to_string().len();
    answer["pad"] = json!("x".repeat(len - unpadded));
    let reply = json_reply(200, &answer);
    assert_eq!(reply.body.len(), len, "FIXTURE: the padded reply's length");
    reply
}

impl Fixture {
    /// The fake answers a call that carries the key with `reply`, and any
    /// other with 401.
    fn answer_keyed(&self, reply: FakeReply) {
        let expected = format!("Bearer {}", self.key);
        self.fake.respond_with(move |request| {
            if request.header("authorization") == Some(expected.as_str()) {
                reply.clone()
            } else {
                json_reply(401, &json!({"error": {"message": "no key"}}))
            }
        });
    }

    /// One rerank call of [`QUERY`] over [`DOCUMENTS`] on the reranker's
    /// seat, under its own undeclared run named `name`, as recall makes one.
    async fn rerank(&self, name: &str) -> LlmResult<LlmResponse> {
        let seat = self
            .runtime
            .seat(ModelRole::Reranker)
            .expect("the key_secret reranker's seat is built");
        let run = self.runtime.undeclared_run(
            name,
            BudgetGuard::with_reserve_units(
                name,
                1_000_000,
                1_000,
                BudgetExhaustionPolicy::Suspend,
            ),
        );
        let call = seat.ladder.generate_within(
            &run,
            rerank_request(seat.model.clone()),
            None,
            &|| true,
            Duration::ZERO,
        );
        tokio::time::timeout(Duration::from_secs(120), call)
            .await
            .expect("the rerank call ended within two minutes")
    }

    fn reads(&self) -> usize {
        self.keys.reads.load(Ordering::SeqCst)
    }

    /// No receipt row holds the key, raw or base64.
    fn assert_no_key_in_receipts(&self) {
        for row in self.receipts.rows() {
            let row = serde_json::to_string(&row).expect("receipt json");
            assert_no_key(&self.key, &row, "a receipt");
        }
    }
}

/// The rerank protocol's call: the query as the first user message, each
/// document one text part of the second, in order.
fn rerank_request(model: ModelId) -> LlmRequest {
    let purpose = CallPurpose::Other {
        name: "rerank".to_owned(),
    };
    let text = |text: &str| ContentPart::Text {
        text: text.to_owned(),
        signature: None,
    };
    LlmRequest {
        model,
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Default::default(),
            tier: TierPrecedence::for_purpose(&purpose, ModelTierRef("rerank".into())),
            purpose,
            class: CallClass::BestEffort,
            response_format: ResponseFormat::Text,
            locality: ModelLocality::ThirdParty,
            host_keyless: false,
            host_paid: false,
        },
        messages: vec![
            LlmMessage {
                role: LlmMessageRole::User,
                content: vec![text(QUERY)],
            },
            LlmMessage {
                role: LlmMessageRole::User,
                content: DOCUMENTS.iter().copied().map(text).collect(),
            },
        ],
        tools: Vec::new(),
        params: Default::default(),
        provider_options: Default::default(),
        host_segments: None,
    }
}

/// The scores a rerank answer carries, in document order.
fn scores(answer: &LlmResponse) -> Vec<f32> {
    let text: String = answer
        .message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text, .. } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("scores {text:?}: {error}"))
}

/// The fixture's broker is sound on any tree: the provider's chat leg is
/// built over the same-user child, so the `[broker]` table, the key door and
/// the provider config stand before the reranker is looked at.
fn assert_fixture(f: &Fixture) {
    let provider = &f.runtime.status().providers[0];
    assert_eq!(
        provider.broker_isolation,
        Some(BrokerIsolation::SameUser),
        "FIXTURE: the key_secret provider sends through the same-user broker child"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_key_secret_reranker_reranks_through_the_broker() {
    let f = fixture();
    assert_fixture(&f);
    assert!(
        f.runtime.seat(ModelRole::Reranker).is_some(),
        "the key_secret reranker's seat is built (main refuses it: no broker rerank shape)"
    );
    f.answer_keyed(json_reply(200, &rerank_answer()));
    let answer = f.rerank("rerank-served").await.expect("reranked");
    assert_eq!(scores(&answer), SCORES, "scores in document order");
    let seen = f.fake.seen();
    assert_eq!(seen.len(), 1, "one send");
    assert_eq!(
        (seen[0].method.as_str(), seen[0].path.as_str()),
        ("POST", "/v1/rerank")
    );
    assert_eq!(
        seen[0].header("authorization"),
        Some(format!("Bearer {}", f.key).as_str()),
        "the broker added the key"
    );
    let body: JsonValue = serde_json::from_slice(&seen[0].body).expect("a JSON body");
    assert_eq!(body["model"], "rerank-small");
    assert_eq!(body["query"], QUERY);
    assert_eq!(body["documents"], json!(DOCUMENTS));
    assert_eq!(f.reads(), 1, "one key read at the door");
    let rows = f.receipts.rows();
    assert!(
        rows.iter().any(|row| matches!(
            &row.event,
            RunEvent::Dispatched {
                broker_isolation: Some(BrokerIsolation::SameUser),
                answered: true,
                ..
            }
        )),
        "the call's dispatch receipt names the broker: {rows:?}"
    );
    f.assert_no_key_in_receipts();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_key_the_rerank_provider_echoes_is_in_no_log_error_or_receipt() {
    let f = fixture();
    assert_fixture(&f);
    // An answer that quotes the key, raw and base64, in its model and usage.
    f.fake.respond_with(|request| {
        let auth = request
            .header("authorization")
            .unwrap_or_default()
            .to_owned();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&auth);
        let mut answer = rerank_answer();
        answer["model"] = json!(format!("rerank-small {auth}"));
        answer["usage"]["note"] = json!(format!("you sent {auth} ({encoded})"));
        json_reply(200, &answer)
    });
    let answer = f.rerank("rerank-echo").await.expect("answered");
    assert_eq!(scores(&answer), SCORES);
    let text = format!("{answer:?}");
    assert_no_key(&f.key, &text, "the answer");
    assert!(
        text.contains("[redacted]"),
        "the broker redacted the echo: {text}"
    );

    // An error that echoes it, in the body and in a header.
    f.fake.respond_with(|request| {
        let auth = request
            .header("authorization")
            .unwrap_or_default()
            .to_owned();
        FakeReply {
            status: 400,
            headers: vec![
                ("content-type".to_owned(), "application/json".to_owned()),
                ("x-echo".to_owned(), auth.clone()),
            ],
            body: json!({"error": {"message": format!("this request was refused for {auth}")}})
                .to_string()
                .into_bytes(),
        }
    });
    let error = f
        .rerank("rerank-echo-error")
        .await
        .expect_err("refused by the provider");
    assert_no_key(&f.key, &format!("{error:?} {error}"), "the error");

    let seen = f.fake.seen();
    assert_eq!(seen.len(), 2, "each call sent once");
    let keyed = format!("Bearer {}", f.key);
    assert!(
        seen.iter()
            .all(|request| request.header("authorization") == Some(keyed.as_str())),
        "every send carried the key the broker added"
    );
    f.assert_no_key_in_receipts();
    let logs = captured_logs();
    assert!(
        logs.contains("same_user"),
        "FIXTURE: the capture holds this process's log lines (the same-user broker warning)"
    );
    assert_no_key(&f.key, &logs, "a log line");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_over_long_rerank_reply_is_refused_at_the_bound() {
    let f = fixture();
    assert_fixture(&f);
    let bound = oneiron_broker::MAX_BODY;
    f.answer_keyed(padded_answer(bound));
    let answer = f
        .rerank("rerank-at-bound")
        .await
        .expect("a reply of exactly the bound answers");
    assert_eq!(scores(&answer), SCORES);
    let sent = f.fake.seen().len();

    f.answer_keyed(padded_answer(bound + 1));
    let refused = f.rerank("rerank-over-bound").await;
    let sends = f.fake.seen().len() - sent;
    eprintln!(
        "## OVER-BOUND sends={sends} answer={:?}",
        refused.as_ref().err()
    );
    assert!(
        refused.is_err(),
        "a reply one byte over the bound is refused, with no scores"
    );
    assert!(sends >= 1, "the over-long call was sent");
    f.assert_no_key_in_receipts();
}
