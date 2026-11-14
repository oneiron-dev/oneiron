//! L6-29: a `key_secret` provider's chat streams through the credential
//! broker, on the runtime's same-user broker child (the built `oneiron-broker`
//! binary) and the vault's real custody door, against a local TLS fake
//! provider. The key is a sentinel made fresh for each case, so no binary
//! holds it.
//!
//! - An OpenAI-compatible streamed chat call goes as the wire's event request,
//!   and its events come back through the broker, with the call's receipt
//!   naming the broker.
//! - An Anthropic streamed call whose provider echoes every form of the key
//!   has none of them in any delta, answer, receipt row or log line; the
//!   answer holds the broker's redaction.
//! - A stream the provider cuts short ends as a stream cut, after the events
//!   the broker had already cleared.
#![cfg(unix)]

use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Once, PoisonError};
use std::time::Duration;

use base64::Engine as _;
use futures_util::StreamExt;
use oneiron::llm::BrokerIsolation;
use oneiron::llm::manifest::ModelRole;
use oneiron::llm::run_admission::{MemoryReceipts, RunEvent};
use oneiron::secret_custody::{CustodyTier, SECRET_SCOPE_READ, SecretBinding};
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, CallClass, CallEnvelope, CallPurpose, ContentPart,
    LlmError, LlmMessage, LlmMessageRole, LlmRequest, LlmStreamEvent, ModelId, ModelLocality,
    ModelTierRef, ResponseFormat, RetryableLlmError, TierPrecedence, Vault, VaultConfig,
};
use oneiron_broker::testing::{FakeProvider, FakeReply};
use oneiron_server::config::models::ModelsConfig;
use oneiron_server::models::{BROKER_EFFECTOR, KeyDoor, ModelRuntime, VaultKeyDoor};
use serde_json::{Value as JsonValue, json};
use zeroize::Zeroizing;

/// The vault secret the provider's key is registered under: the handle.
const HANDLE: &str = "stream-provider-key";

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
    format!("stream-sentinel-{nanos:x}-{:x}", std::process::id())
}

/// Every form of the key the broker strips.
fn key_forms(key: &str) -> Vec<String> {
    let mut forms = Vec::new();
    forms.push(key.to_owned());
    forms.push(format!("Bearer {key}"));
    forms.push(base64::engine::general_purpose::STANDARD.encode(key));
    forms.push(base64::engine::general_purpose::STANDARD_NO_PAD.encode(key));
    forms.push(base64::engine::general_purpose::URL_SAFE.encode(key));
    forms.push(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key));
    let json = serde_json::to_string(key).expect("key json");
    forms.push(json[1..json.len() - 1].to_owned());
    forms.push(percent_encode(key));
    forms
}

/// The key with every byte outside `A-Za-z0-9-._~` as `%XX`.
fn percent_encode(key: &str) -> String {
    let mut out = String::new();
    for byte in key.bytes() {
        if matches!(
            byte,
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~'
        ) {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// No form of `key` is in `text`.
fn assert_no_key(key: &str, text: &str, what: &str) {
    for form in key_forms(key) {
        assert!(
            !text.contains(form.as_str()),
            "the key is in {what}: {form:?} in {text:?}"
        );
    }
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

/// A runtime whose `paid` provider of `kind`, its key the vault secret
/// [`HANDLE`], serves the `checker` seat through the same-user broker child.
fn fixture(kind: &str) -> Fixture {
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
kind = "{kind}"
base_url = "{origin}"
key_secret = "{HANDLE}"
revision = "v1"
timeout_secs = 20

[roles.checker]
rungs = [{{ model = "paid:chat-small" }}]

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

/// A plain text call for `model`, with no params or provider options, so the
/// ladder streams it.
fn request(model: ModelId, text: &str) -> LlmRequest {
    LlmRequest {
        model,
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Default::default(),
            purpose: CallPurpose::AnswerGen,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::AnswerGen,
                ModelTierRef("answer".into()),
            ),
            response_format: ResponseFormat::Text,
            locality: ModelLocality::ThirdParty,
            host_keyless: false,
            host_paid: false,
        },
        messages: vec![LlmMessage {
            role: LlmMessageRole::User,
            content: vec![ContentPart::Text {
                text: text.into(),
                signature: None,
            }],
        }],
        tools: Vec::new(),
        params: Default::default(),
        provider_options: Default::default(),
        host_segments: None,
    }
}

fn text_of(message: &LlmMessage) -> String {
    message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text, .. } => Some(text.as_str()),
            _ => None,
        })
        .collect()
}

impl Fixture {
    /// One streamed chat call on the checker's seat, under its own
    /// undeclared run named `name`: every event it yields, and the error it
    /// ends with, if any.
    async fn stream(&self, name: &str) -> (Vec<LlmStreamEvent>, Option<LlmError>) {
        let seat = self
            .runtime
            .seat(ModelRole::Checker)
            .expect("the key_secret checker's seat is built");
        let run = self.runtime.undeclared_run(
            name,
            BudgetGuard::with_reserve_units(
                name,
                1_000_000,
                1_000,
                BudgetExhaustionPolicy::Suspend,
            ),
        );
        let mut stream = seat
            .ladder
            .stream(&run, request(seat.model.clone(), "hello"), None)
            .expect("the stream opens");
        tokio::time::timeout(Duration::from_secs(120), async {
            let mut events = Vec::new();
            let mut error = None;
            while let Some(item) = stream.next().await {
                match item {
                    Ok(event) => events.push(event),
                    Err(failure) => {
                        error = Some(failure);
                        break;
                    }
                }
            }
            (events, error)
        })
        .await
        .expect("the stream ended within two minutes")
    }

    fn reads(&self) -> usize {
        self.keys.reads.load(Ordering::SeqCst)
    }

    /// No receipt row holds a form of the key.
    fn assert_no_key_in_receipts(&self) {
        for row in self.receipts.rows() {
            let row = serde_json::to_string(&row).expect("receipt json");
            assert_no_key(&self.key, &row, "a receipt");
        }
    }
}

/// The fixture's broker is sound on any tree: the provider's chat leg is
/// built over the same-user child, so the `[broker]` table, the key door and
/// the provider config stand before the stream is looked at.
fn assert_fixture(f: &Fixture) {
    let provider = &f.runtime.status().providers[0];
    assert_eq!(
        provider.broker_isolation,
        Some(BrokerIsolation::SameUser),
        "FIXTURE: the key_secret provider sends through the same-user broker child"
    );
}

/// An OpenAI-compatible event stream spelling `Hello, owen` in three deltas,
/// then a finish and its usage.
fn openai_stream_body() -> String {
    let chunks = [
        r#"{"id":"c1","object":"chat.completion.chunk","model":"chat-small","choices":[{"index":0,"delta":{"role":"assistant","content":"Hel"},"finish_reason":null}]}"#,
        r#"{"id":"c1","object":"chat.completion.chunk","model":"chat-small","choices":[{"index":0,"delta":{"role":"assistant","content":"lo, "},"finish_reason":null}]}"#,
        r#"{"id":"c1","object":"chat.completion.chunk","model":"chat-small","choices":[{"index":0,"delta":{"role":"assistant","content":"owen"},"finish_reason":null}]}"#,
        r#"{"id":"c1","object":"chat.completion.chunk","model":"chat-small","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
        r#"{"id":"c1","object":"chat.completion.chunk","model":"chat-small","choices":[],"usage":{"prompt_tokens":3,"completion_tokens":3,"total_tokens":6}}"#,
    ];
    let mut body = String::new();
    for chunk in chunks {
        body.push_str("data: ");
        body.push_str(chunk);
        body.push_str("\n\n");
    }
    body.push_str("data: [DONE]\n\n");
    body
}

/// An Anthropic event stream whose four deltas echo the key raw, as a
/// bearer, base64 and percent-encoded. Each echo comes whole in one event:
/// the model never sees the key, so the only echoes are the provider's own
/// texts, which come whole. A form split across two reads is the broker's
/// own `strip.rs` unit tests' case.
fn anthropic_stream_body(key: &str) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(key);
    let pct = percent_encode(key);
    let deltas = [
        format!("raw {key} "),
        format!("bearer Bearer {key} "),
        format!("b64 {b64} "),
        format!("pct {pct} end"),
    ];
    let mut body = String::new();
    body.push_str("event: message_start\ndata: ");
    body.push_str(
        &json!({
            "type": "message_start",
            "message": {
                "id": "m1",
                "type": "message",
                "role": "assistant",
                "model": "chat-small",
                "content": [],
                "usage": {"input_tokens": 3, "output_tokens": 0}
            }
        })
        .to_string(),
    );
    body.push_str("\n\n");
    body.push_str("event: content_block_start\ndata: ");
    body.push_str(
        &json!({
            "type": "content_block_start",
            "index": 0,
            "content_block": {"type": "text", "text": ""}
        })
        .to_string(),
    );
    body.push_str("\n\n");
    for text in deltas {
        body.push_str("event: content_block_delta\ndata: ");
        body.push_str(
            &json!({
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": text}
            })
            .to_string(),
        );
        body.push_str("\n\n");
    }
    body.push_str("event: content_block_stop\ndata: ");
    body.push_str(&json!({"type": "content_block_stop", "index": 0}).to_string());
    body.push_str("\n\n");
    body.push_str("event: message_delta\ndata: ");
    body.push_str(
        &json!({
            "type": "message_delta",
            "delta": {"stop_reason": "end_turn"},
            "usage": {"output_tokens": 9}
        })
        .to_string(),
    );
    body.push_str("\n\n");
    body.push_str("event: message_stop\ndata: ");
    body.push_str(&json!({"type": "message_stop"}).to_string());
    body.push_str("\n\n");
    body
}

#[tokio::test(flavor = "multi_thread")]
async fn a_key_secret_openai_chat_streams_its_events_through_the_broker() {
    let f = fixture("openai-compat");
    assert_fixture(&f);
    assert!(
        f.runtime.seat(ModelRole::Checker).is_some(),
        "the key_secret checker's seat is built"
    );
    let key = f.key.clone();
    f.fake.respond_with(move |request| {
        let expected = format!("Bearer {key}");
        let streamed = serde_json::from_slice::<JsonValue>(&request.body)
            .ok()
            .and_then(|body| body.get("stream").and_then(JsonValue::as_bool))
            .unwrap_or(false);
        if request.header("authorization") == Some(expected.as_str()) && streamed {
            FakeReply {
                status: 200,
                headers: vec![("content-type".to_owned(), "text/event-stream".to_owned())],
                body: openai_stream_body().into_bytes(),
            }
        } else {
            FakeReply::json(
                400,
                &json!({"error": {"message": "expected a keyed stream"}}),
            )
        }
    });
    let (events, error) = f.stream("stream-openai").await;
    assert!(error.is_none(), "no error: {error:?}");
    let mut concatenated = String::new();
    let mut delta_count = 0;
    let mut done_text = None;
    for event in &events {
        match event {
            LlmStreamEvent::TextDelta { text, .. } => {
                delta_count += 1;
                concatenated.push_str(text);
            }
            LlmStreamEvent::Done { message, .. } => {
                done_text = Some(text_of(message));
            }
            _ => {}
        }
    }
    assert!(delta_count >= 2, "at least two deltas before Done");
    assert_eq!(
        concatenated.as_str(),
        "Hello, owen",
        "delta texts concatenate"
    );
    assert_eq!(
        done_text.as_deref(),
        Some("Hello, owen"),
        "the Done message text"
    );
    let seen = f.fake.seen();
    assert_eq!(seen.len(), 1, "one send");
    assert!(
        seen[0].path.ends_with("/v1/chat/completions"),
        "to chat completions"
    );
    let body: JsonValue = serde_json::from_slice(&seen[0].body).expect("a JSON body");
    assert_eq!(body["stream"], json!(true), "the event request");
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
    assert!(
        rows.iter().any(|row| serde_json::to_string(row)
            .expect("receipt json")
            .contains("same_user")),
        "a receipt row names same_user"
    );
    f.assert_no_key_in_receipts();
    let logs = captured_logs();
    assert!(
        logs.contains("same_user"),
        "FIXTURE: the capture holds this process's log lines"
    );
    assert_no_key(&f.key, &logs, "a log line");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_key_secret_anthropic_stream_redacts_every_echoed_key_form() {
    let f = fixture("anthropic-compat");
    assert_fixture(&f);
    assert!(
        f.runtime.seat(ModelRole::Checker).is_some(),
        "the key_secret checker's seat is built"
    );
    let key = f.key.clone();
    let stream_body = anthropic_stream_body(&key);
    f.fake.respond_with(move |request| {
        let streamed = serde_json::from_slice::<JsonValue>(&request.body)
            .ok()
            .and_then(|body| body.get("stream").and_then(JsonValue::as_bool))
            .unwrap_or(false);
        if request.header("x-api-key") == Some(key.as_str()) && streamed {
            FakeReply {
                status: 200,
                headers: vec![("content-type".to_owned(), "text/event-stream".to_owned())],
                body: stream_body.clone().into_bytes(),
            }
        } else {
            FakeReply::json(
                400,
                &json!({"error": {"message": "expected a keyed stream"}}),
            )
        }
    });
    let (events, error) = f.stream("stream-anthropic").await;
    assert!(error.is_none(), "no error: {error:?}");
    let mut done_text = None;
    for event in &events {
        match event {
            LlmStreamEvent::TextDelta { text, .. } => {
                assert_no_key(&f.key, text, "a delta");
            }
            LlmStreamEvent::Done { message, .. } => {
                let text = text_of(message);
                assert_no_key(&f.key, &text, "the Done message");
                assert!(
                    text.contains("[redacted]"),
                    "the broker redacted the echo: {text}"
                );
                done_text = Some(text);
            }
            _ => {}
        }
    }
    assert!(done_text.is_some(), "Done arrives");
    let seen = f.fake.seen();
    assert_eq!(seen.len(), 1, "one send");
    assert_eq!(
        seen[0].header("x-api-key"),
        Some(f.key.as_str()),
        "the key the broker added"
    );
    f.assert_no_key_in_receipts();
    let logs = captured_logs();
    assert_no_key(&f.key, &logs, "a log line");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cut_key_secret_stream_ends_as_a_stream_cut() {
    let f = fixture("openai-compat");
    assert_fixture(&f);
    let key = f.key.clone();
    f.fake.respond_with(move |request| {
        let expected = format!("Bearer {key}");
        let streamed = serde_json::from_slice::<JsonValue>(&request.body)
            .ok()
            .and_then(|body| body.get("stream").and_then(JsonValue::as_bool))
            .unwrap_or(false);
        if request.header("authorization") == Some(expected.as_str()) && streamed {
            let mut body = String::new();
            body.push_str("data: ");
            body.push_str(r#"{"id":"c1","object":"chat.completion.chunk","model":"chat-small","choices":[{"index":0,"delta":{"role":"assistant","content":"partial"},"finish_reason":null}]}"#);
            body.push_str("\n\n");
            body.push_str(": ");
            body.push_str(&"x".repeat(2048));
            body.push_str("\n\n");
            let length = body.len() + 4096;
            FakeReply {
                status: 200,
                headers: vec![
                    ("content-type".to_owned(), "text/event-stream".to_owned()),
                    ("content-length".to_owned(), length.to_string()),
                ],
                body: body.into_bytes(),
            }
        } else {
            FakeReply::json(400, &json!({"error": {"message": "expected a keyed stream"}}))
        }
    });
    let (events, error) = f.stream("stream-cut").await;
    let mut delta_count = 0;
    let mut first_delta = None;
    let mut saw_done = false;
    for event in &events {
        match event {
            LlmStreamEvent::TextDelta { text, .. } => {
                delta_count += 1;
                if first_delta.is_none() {
                    first_delta = Some(text.as_str());
                }
            }
            LlmStreamEvent::Done { .. } => saw_done = true,
            _ => {}
        }
    }
    assert_eq!(delta_count, 1, "one delta before the cut");
    assert_eq!(first_delta, Some("partial"), "the partial delta");
    assert!(!saw_done, "no Done after a cut");
    assert!(
        matches!(
            &error,
            Some(LlmError::Retryable(RetryableLlmError::StreamCut))
        ),
        "a cut ends as StreamCut: {error:?}"
    );
    f.assert_no_key_in_receipts();
    let logs = captured_logs();
    assert_no_key(&f.key, &logs, "a log line");
}
